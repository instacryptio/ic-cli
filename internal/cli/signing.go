package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/instacryptio/ic-cli/internal/utils"
	"github.com/instacryptio/icfx/bundle"
	"github.com/instacryptio/icfx/cloud"
	"github.com/instacryptio/icfx/crypto"
)

// keySigner signs with a raw ML-DSA-65 private key — used to seal rotation and
// revocation bundles with the key being rotated away from / revoked.
type keySigner struct{ key []byte }

func (k keySigner) Sign(data []byte) ([]byte, error) { return crypto.Sign(data, k.key) }

// broadcastRotationToCloud posts a signed rotation to every cloud contact,
// best-effort: if cloud isn't configured or the user isn't signed in it skips
// silently (the exported .rotate file is the out-of-band channel). When it does
// run it reports which contacts were notified.
func broadcastRotationToCloud(rot bundle.RotationBundle) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, err := requireCloudAuth(ctx)
	if err != nil {
		return
	}
	store, err := newContactStore()
	if err != nil {
		return
	}
	rep, err := cloud.BroadcastRotation(ctx, c, store, rot)
	if err != nil {
		fmt.Println(utils.RenderDim("Cloud rotation broadcast failed: " + err.Error()))
		return
	}
	reportBroadcast(rep)
}

// broadcastRevocationToCloud is the revocation counterpart of the above.
func broadcastRevocationToCloud(rev bundle.RevocationBundle) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, err := requireCloudAuth(ctx)
	if err != nil {
		return
	}
	store, err := newContactStore()
	if err != nil {
		return
	}
	rep, err := cloud.BroadcastRevocation(ctx, c, store, rev)
	if err != nil {
		fmt.Println(utils.RenderDim("Cloud revocation broadcast failed: " + err.Error()))
		return
	}
	reportBroadcast(rep)
}

func reportBroadcast(rep cloud.BroadcastReport) {
	if len(rep.Sent) > 0 {
		fmt.Println(utils.RenderSuccess(fmt.Sprintf("Notified %d cloud contact(s) of your key change.", len(rep.Sent))))
	}
	if len(rep.Skipped) > 0 {
		fmt.Println(utils.RenderDim(fmt.Sprintf("%d non-cloud contact(s) must be sent the exported bundle out-of-band.", len(rep.Skipped))))
	}
	if len(rep.Failed) > 0 {
		fmt.Println(utils.RenderWarning(fmt.Sprintf("%d cloud contact(s) could not be notified (will retry on their next sync is not automatic — re-run rotate export).", len(rep.Failed))))
	}
}
