//go:build darwin

package browser

func executable() (string, error) {
	return "open", nil
}
