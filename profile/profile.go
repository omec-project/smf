// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package profile

import (
	"encoding/json"
	"net/http"
	"os"
	"runtime"
	"runtime/pprof"

	"github.com/free5gc/smf/logger"
)

type memoryparams struct {
	HeapSys      uint64 `json:"heapSys"`
	HeapAlloc    uint64 `json:"heapAlloc"`
	HeapIdle     uint64 `json:"heapIdle"`
	HeapReleased uint64 `json:"heapReleased"`
	HeapInuse    uint64 `json:"heapInuse`
}

func InitProfile() {
	logger.ProfileLog.Infof("Initiating profiling on port 5001")

	http.HandleFunc("/profile/memory", GenerateMemProfile)
	http.HandleFunc("/profile/memorystats", GenerateMemStatsProfile)
	http.HandleFunc("/profile/cpu", GenerateCpuProfile)
	http.HandleFunc("/profile/block", GenerateBlockProfile)
	http.HandleFunc("/profile/goroutine", GenerateGoroutineProfile)

	http.ListenAndServe(":5001", nil)
}

func GenerateMemProfile(w http.ResponseWriter, r *http.Request) {

	logger.ProfileLog.Infof("Generating memory profile file with the name memory.out")

	f, err := os.Create("memory.out")
	if err != nil {
		logger.ProfileLog.Errorf("Could not create file : ", err)
		os.Exit(2)
	}
	runtime.GC() // materialize all statistics
	if err = pprof.WriteHeapProfile(f); err != nil {
		logger.ProfileLog.Errorf("Could not write heap profile into the file : ", err)
		os.Exit(2)
	}
	f.Close()
}

func GenerateCpuProfile(w http.ResponseWriter, r *http.Request) {

	logger.ProfileLog.Infof("Generating cpu profile file with the name cpu.out")

	f, err := os.Create("cpu.out")
	if err != nil {
		logger.ProfileLog.Errorf("Could not create cpu file : ", err)
	}
	if err := pprof.StartCPUProfile(f); err != nil {
		logger.ProfileLog.Errorf("Could not write CPU profile into the file : ", err)
	}
	defer pprof.StopCPUProfile()

	f.Close()
}

func GenerateBlockProfile(w http.ResponseWriter, r *http.Request) {

	logger.ProfileLog.Infof("Generating block profile file with the name blockprof.out")

	f, err := os.Create("blockprof.out")

	if err != nil {
		logger.ProfileLog.Errorf("Could not create block file : ", err)
	}
	pprof.Lookup("block").WriteTo(f, 0)
	f.Close()
}

func GenerateGoroutineProfile(w http.ResponseWriter, r *http.Request) {

	logger.ProfileLog.Infof("Generating go routine profile file with the name goprof.out")

	f, err := os.Create("goprof.out")

	if err != nil {
		logger.ProfileLog.Errorf("Could not create go routine file : ", err)
		os.Exit(2)
	}
	f.Close()
}

func GenerateMemStatsProfile(w http.ResponseWriter, r *http.Request) {

	logger.ProfileLog.Infof("Generating stats for heap memory")

	var memstats runtime.MemStats
	runtime.ReadMemStats(&memstats)
	stat := &memoryparams{
		HeapSys:      memstats.HeapSys,
		HeapAlloc:    memstats.HeapAlloc,
		HeapIdle:     memstats.HeapIdle,
		HeapReleased: memstats.HeapReleased,
	}

	jsonResp, err := json.Marshal(stat)
	if err != nil {
		logger.ProfileLog.Errorf("Could not create json for memory stats : ", err)
	}
	w.Write(jsonResp)
}
