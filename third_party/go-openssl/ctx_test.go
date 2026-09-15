// Copyright (C) 2017. See AUTHORS.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package openssl

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCtxTimeoutOption(t *testing.T) {
	ctx, _ := NewCtx()
	oldTimeout1 := ctx.GetTimeout()
	newTimeout1 := oldTimeout1 + (time.Duration(99) * time.Second)
	oldTimeout2 := ctx.SetTimeout(newTimeout1)
	newTimeout2 := ctx.GetTimeout()

	require.Equal(t, oldTimeout1, oldTimeout2, "SetTimeout() returns something undocumented")
	require.Equal(t, newTimeout1, newTimeout2, "SetTimeout() does not save anything to ctx")
}

func TestCtxSessCacheSizeOption(t *testing.T) {
	ctx, _ := NewCtx()
	oldSize1 := ctx.SessGetCacheSize()
	newSize1 := oldSize1 + 42
	oldSize2 := ctx.SessSetCacheSize(newSize1)
	newSize2 := ctx.SessGetCacheSize()

	require.Equal(t, oldSize1, oldSize2, "SessSetCacheSize() returns something undocumented")
	require.Equal(t, newSize1, newSize2, "SessSetCacheSize() does not save anything to ctx")
}

func TestCtxClose(t *testing.T) {
	ctx, err := NewCtx()
	require.Nil(t, err)
	require.NotNil(t, ctx)

	err = ctx.Close()
	require.Nil(t, err)

	// Check double closing.
	err = ctx.Close()
	require.Nil(t, err)
}
