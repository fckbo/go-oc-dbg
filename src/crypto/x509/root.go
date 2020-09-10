// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import ( 
	"sync"
	"fmt"
	"time"
)

var (
	once           sync.Once
	systemRoots    *CertPool
	systemRootsErr error
)

func systemRootsPool() *CertPool {
        fmt.Println(time.Now().Format(time.StampNano)," FB !!! crypto/x509/root->systemRootsPool")
	once.Do(initSystemRoots)
        fmt.Println(time.Now().Format(time.StampNano)," FB !!! crypto/x509/root<-systemRootsPool")
	return systemRoots
}

func initSystemRoots() {
        fmt.Println(time.Now().Format(time.StampNano)," FB !!! crypto/x509/root->initSystemRoots")
	systemRoots, systemRootsErr = loadSystemRoots()
	if systemRootsErr != nil {
        	fmt.Println(time.Now().Format(time.StampNano)," FB !!! crypto/x509/root<-initSystemRoots to nil")
		systemRoots = nil
	}
        fmt.Println(time.Now().Format(time.StampNano)," FB !!! crypto/x509/root<-initSystemRoots")
}
