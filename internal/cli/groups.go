package cli

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	"github.com/instacryptio/ic-cli/internal/utils"
	"github.com/instacryptio/icfx/contacts"
	"github.com/instacryptio/icfx/groups"
)

var groupsCmd = &cobra.Command{
	Use:     "groups",
	Aliases: []string{"g", "group"},
	Short:   "Manage contact groups (encrypt/share to several people at once)",
}

// resolveGroupMembers maps member contact aliases to their stable contact IDs,
// deduping. A contact with no ID yet is assigned one (persisted), so groups can
// reference it reliably across renames — same behaviour as the app.
func resolveGroupMembers(memberAliases []string) ([]string, error) {
	contactStore, err := newContactStore()
	if err != nil {
		return nil, err
	}
	contactList, err := contactStore.Load()
	if err != nil {
		return nil, fmt.Errorf("loading contacts: %w", err)
	}
	ids := make([]string, 0, len(memberAliases))
	seen := map[string]struct{}{}
	assigned := false
	for _, alias := range memberAliases {
		c, ferr := contacts.FindByAlias(contactList, alias)
		if ferr != nil {
			return nil, fmt.Errorf("contact %q not found", alias)
		}
		if contacts.EnsureID(c) {
			assigned = true
		}
		if _, dup := seen[c.ID]; dup {
			continue
		}
		seen[c.ID] = struct{}{}
		ids = append(ids, c.ID)
	}
	if assigned {
		if err := contactStore.Save(contactList); err != nil {
			return nil, fmt.Errorf("persisting contact ids: %w", err)
		}
	}
	return ids, nil
}

// resolveGroupRef finds a group by exact name, then by ID.
func resolveGroupRef(list []groups.Group, ref string) (*groups.Group, error) {
	if g, err := groups.FindByName(list, ref); err == nil {
		return g, nil
	}
	return groups.FindByID(list, ref)
}

// memberAliases resolves a group's member IDs to current contact aliases,
// skipping members whose contact was deleted (dangling IDs).
func memberAliases(g groups.Group, contactList []contacts.Contact) []string {
	out := make([]string, 0, len(g.MemberIDs))
	for _, mid := range g.MemberIDs {
		if c, err := contacts.FindByID(contactList, mid); err == nil {
			out = append(out, c.Alias)
		}
	}
	return out
}

var groupsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all groups",
	RunE: func(cmd *cobra.Command, args []string) error {
		asJSON, _ := cmd.Flags().GetBool("json")
		gs, err := groups.NewStore()
		if err != nil {
			return err
		}
		list, err := gs.List()
		if err != nil {
			return fmt.Errorf("loading groups: %w", err)
		}
		if asJSON {
			data, err := json.MarshalIndent(list, "", "  ")
			if err != nil {
				return fmt.Errorf("marshaling groups: %w", err)
			}
			fmt.Println(string(data))
			return nil
		}
		if len(list) == 0 {
			fmt.Println("No groups found.")
			return nil
		}
		contactStore, _ := newContactStore()
		contactList, _ := contactStore.Load()
		fmt.Println(utils.RenderTitle("Groups"))
		fmt.Println()
		for _, g := range list {
			aliases := memberAliases(g, contactList)
			fmt.Printf("  %s %s\n",
				lipgloss.NewStyle().Bold(true).Render(utils.SanitizeTerminal(g.Name)),
				utils.RenderDim(fmt.Sprintf("(%d) %s", len(aliases), utils.SanitizeTerminal(strings.Join(aliases, ", ")))),
			)
		}
		return nil
	},
}

var groupsShowCmd = &cobra.Command{
	Use:   "show <name|id>",
	Short: "Show a group's members",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		asJSON, _ := cmd.Flags().GetBool("json")
		gs, err := groups.NewStore()
		if err != nil {
			return err
		}
		list, err := gs.List()
		if err != nil {
			return fmt.Errorf("loading groups: %w", err)
		}
		g, err := resolveGroupRef(list, args[0])
		if err != nil {
			return fmt.Errorf("group %q not found", args[0])
		}
		contactStore, _ := newContactStore()
		contactList, _ := contactStore.Load()

		if asJSON {
			type memberView struct {
				ID          string `json:"id"`
				Alias       string `json:"alias"`
				Fingerprint string `json:"fingerprint"`
			}
			members := make([]memberView, 0, len(g.MemberIDs))
			for _, mid := range g.MemberIDs {
				if c, ferr := contacts.FindByID(contactList, mid); ferr == nil {
					members = append(members, memberView{ID: c.ID, Alias: c.Alias, Fingerprint: c.Fingerprint})
				}
			}
			data, err := json.MarshalIndent(struct {
				ID      string       `json:"id"`
				Name    string       `json:"name"`
				Members []memberView `json:"members"`
			}{ID: g.ID, Name: g.Name, Members: members}, "", "  ")
			if err != nil {
				return fmt.Errorf("marshaling group: %w", err)
			}
			fmt.Println(string(data))
			return nil
		}

		fmt.Println(utils.RenderTitle(g.Name))
		fmt.Println()
		printed := 0
		for _, mid := range g.MemberIDs {
			c, ferr := contacts.FindByID(contactList, mid)
			if ferr != nil {
				continue // dangling member (contact deleted)
			}
			fmt.Printf("  %s %s\n",
				lipgloss.NewStyle().Bold(true).Render(utils.SanitizeTerminal(c.Alias)),
				utils.RenderDim(c.Fingerprint),
			)
			printed++
		}
		if printed == 0 {
			fmt.Println(utils.RenderDim("  (no members)"))
		}
		return nil
	},
}

var groupsAddCmd = &cobra.Command{
	Use:   "add <name>",
	Short: "Create a group from contact aliases",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := strings.TrimSpace(args[0])
		if name == "" {
			return fmt.Errorf("group name is required")
		}
		members, _ := cmd.Flags().GetStringSlice("member")
		ids, err := resolveGroupMembers(members)
		if err != nil {
			return err
		}
		gs, err := groups.NewStore()
		if err != nil {
			return err
		}
		if _, err := gs.Add(name, ids); err != nil {
			if err == groups.ErrAlreadyExists {
				return fmt.Errorf("a group named %q already exists", name)
			}
			return fmt.Errorf("adding group: %w", err)
		}
		fmt.Println(utils.RenderSuccess("Group added: ") + name)
		return nil
	},
}

var groupsEditCmd = &cobra.Command{
	Use:   "edit <name|id>",
	Short: "Rename a group and/or replace its members",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		gs, err := groups.NewStore()
		if err != nil {
			return err
		}
		list, err := gs.List()
		if err != nil {
			return fmt.Errorf("loading groups: %w", err)
		}
		g, err := resolveGroupRef(list, args[0])
		if err != nil {
			return fmt.Errorf("group %q not found", args[0])
		}

		name := g.Name
		if cmd.Flags().Changed("name") {
			name, _ = cmd.Flags().GetString("name")
			if strings.TrimSpace(name) == "" {
				return fmt.Errorf("group name cannot be empty")
			}
		}
		memberIDs := g.MemberIDs
		if cmd.Flags().Changed("member") {
			members, _ := cmd.Flags().GetStringSlice("member")
			memberIDs, err = resolveGroupMembers(members)
			if err != nil {
				return err
			}
		}
		if err := gs.Edit(g.ID, name, memberIDs); err != nil {
			return fmt.Errorf("updating group: %w", err)
		}
		fmt.Println(utils.RenderSuccess("Group updated: ") + name)
		return nil
	},
}

var groupsRemoveCmd = &cobra.Command{
	Use:     "remove <name|id>",
	Aliases: []string{"rm", "delete"},
	Short:   "Delete a group (contacts are not affected)",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		gs, err := groups.NewStore()
		if err != nil {
			return err
		}
		list, err := gs.List()
		if err != nil {
			return fmt.Errorf("loading groups: %w", err)
		}
		g, err := resolveGroupRef(list, args[0])
		if err != nil {
			return fmt.Errorf("group %q not found", args[0])
		}
		if err := gs.Remove(g.ID); err != nil {
			return fmt.Errorf("removing group: %w", err)
		}
		fmt.Println(utils.RenderSuccess("Group removed: ") + g.Name)
		return nil
	},
}

func init() {
	groupsListCmd.Flags().Bool("json", false, "Output as JSON")
	groupsShowCmd.Flags().Bool("json", false, "Output as JSON")
	groupsAddCmd.Flags().StringSliceP("member", "m", nil, "Member contact alias (repeatable, or comma-separated)")
	groupsEditCmd.Flags().String("name", "", "New group name")
	groupsEditCmd.Flags().StringSliceP("member", "m", nil, "Replace members with these contact aliases")

	groupsCmd.AddCommand(groupsListCmd, groupsShowCmd, groupsAddCmd, groupsEditCmd, groupsRemoveCmd)
	rootCmd.AddCommand(groupsCmd)
}
