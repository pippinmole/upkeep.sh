//go:build !linux

package imagescan

import (
	"os"
	"sync/atomic"
	"syscall"
)

// Outside Linux (development only) there is no RSS watchdog and no
// parent-death signal: GOMEMLIMIT and the timeout still apply.

func childSysProcAttr() *syscall.SysProcAttr { return nil }

func watchMemory(*os.Process, int64, *atomic.Bool) (stop func()) { return func() {} }
