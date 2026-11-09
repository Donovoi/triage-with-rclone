package hdfs

import (
	"context"
	"os"
)

// ReadDir reads the directory named by dirname and returns a list of sorted
// directory entries.
//
// The os.FileInfo values returned will not have block location attached to
// the struct returned by Sys().
func (c *Client) ReadDir(dirname string) ([]os.FileInfo, error) {
	return c.ReadDirContext(context.Background(), dirname)
}

// ReadDirContext reads a directory with cancellation for metadata and all pages.
func (c *Client) ReadDirContext(ctx context.Context, dirname string) ([]os.FileInfo, error) {
	f, err := c.OpenContext(ctx, dirname)
	if err != nil {
		return nil, err
	}

	return f.ReaddirContext(ctx, 0)
}
