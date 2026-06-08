//go:build windows

//lint:file-ignore U1000 exports

package etw

import (
	"syscall"
)

var (
	tdh                                            = syscall.NewLazyDLL("tdh.dll")
	tdhDll                                         = syscall.MustLoadDLL("tdh.dll")
	tdhEnumerateProviderFieldInformation           = tdh.NewProc("TdhEnumerateProviderFieldInformation")
	tdhEnumerateProviderFilters                    = tdh.NewProc("TdhEnumerateProviderFilters")
	tdhCreatePayloadFilter                         = tdh.NewProc("TdhCreatePayloadFilter")
	tdhEnumerateProviders                          = tdh.NewProc("TdhEnumerateProviders")
	tdhEnumerateRemoteWBEMProviderFieldInformation = tdh.NewProc("TdhEnumerateRemoteWBEMProviderFieldInformation")
	tdhEnumerateRemoteWBEMProviders                = tdh.NewProc("TdhEnumerateRemoteWBEMProviders")
	tdhFormatProperty                              = tdhDll.MustFindProc("TdhFormatProperty")
	tdhGetAllEventsInformation                     = tdh.NewProc("TdhGetAllEventsInformation")
	tdhGetEventInformation                         = tdhDll.MustFindProc("TdhGetEventInformation")
	tdhGetEventMapInformation                      = tdhDll.MustFindProc("TdhGetEventMapInformation")
	tdhGetProperty                                 = tdhDll.MustFindProc("TdhGetProperty")
	tdhGetPropertyOffsetAndSize                    = tdhDll.MustFindProc("TdhGetPropertyOffsetAndSize")
	tdhGetPropertySize                             = tdhDll.MustFindProc("TdhGetPropertySize")
	tdhLoadManifest                                = tdhDll.MustFindProc("TdhLoadManifest")
	tdhQueryProviderFieldInformation               = tdhDll.MustFindProc("TdhQueryProviderFieldInformation")
	tdhQueryRemoteWBEMProviderFieldInformation     = tdh.NewProc("TdhQueryRemoteWBEMProviderFieldInformation")
	tdhUnloadManifest                              = tdh.NewProc("TdhUnloadManifest")
)
