// SPDX-FileCopyrightText: 2025 Canonical Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//
/*
 * NRF Registration Unit Testcases
 *
 */
package nfregistration

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/omec-project/openapi/models"
	"github.com/omec-project/openapi/nfConfigApi"
	"github.com/omec-project/smf/consumer"
)

var (
	sessionConfigs   []nfConfigApi.SessionManagement
	port             int32 = 8805
	sd                     = "010203"
	sessionConfigOne       = nfConfigApi.SessionManagement{
		SliceName: "slice-internet",
		PlmnId: nfConfigApi.PlmnId{
			Mcc: "001",
			Mnc: "01",
		},
		Snssai: nfConfigApi.Snssai{
			Sst: 1,
			Sd:  &sd,
		},
		IpDomain: []nfConfigApi.IpDomain{
			{
				DnnName:  "internet",
				DnsIpv4:  "8.8.8.8",
				UeSubnet: "10.10.0.0/16",
				Mtu:      1400,
			},
		},
		Upf: &nfConfigApi.Upf{
			Hostname: "upf-1",
			Port:     &port,
		},
		GnbNames: []string{"gnb1", "gnb2"},
	}
)

func makeSessionConfig(sliceName, mcc, mnc, sst string, sd string, dnnName, ueSubnet, hostname string, port int32) (nfConfigApi.SessionManagement, error) {
	sstUint64, err := strconv.ParseUint(sst, 10, 8)
	if err != nil {
		return nfConfigApi.SessionManagement{}, fmt.Errorf("invalid SST value: %s, error: %w", sst, err)
	}
	sstint := int32(sstUint64)

	return nfConfigApi.SessionManagement{
		SliceName: sliceName,
		PlmnId: nfConfigApi.PlmnId{
			Mcc: mcc,
			Mnc: mnc,
		},
		Snssai: nfConfigApi.Snssai{
			Sst: sstint,
			Sd:  &sd,
		},
		IpDomain: []nfConfigApi.IpDomain{
			{
				DnnName:  dnnName,
				DnsIpv4:  "8.8.8.8",
				UeSubnet: ueSubnet,
				Mtu:      1400,
			},
		},
		Upf: &nfConfigApi.Upf{
			Hostname: hostname,
			Port:     &port,
		},
		GnbNames: []string{"gnb1", "gnb2"},
	}, nil
}

func TestNfRegistrationService_WhenEmptyConfig_ThenDeregisterNFAndStopTimer(t *testing.T) {
	isDeregisterNFCalled := false
	testCases := []struct {
		name                         string
		sendDeregisterNFInstanceMock func() error
	}{
		{
			name: "Success",
			sendDeregisterNFInstanceMock: func() error {
				isDeregisterNFCalled = true
				return nil
			},
		},
		{
			name: "ErrorInDeregisterNFInstance",
			sendDeregisterNFInstanceMock: func() error {
				isDeregisterNFCalled = true
				return errors.New("mock error")
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			keepAliveTimer = time.NewTimer(60 * time.Second)
			isRegisterNFCalled := false
			isDeregisterNFCalled = false
			originalDeregisterNF := consumer.SendDeregisterNFInstance
			originalRegisterNF := registerNF
			defer func() {
				consumer.SendDeregisterNFInstance = originalDeregisterNF
				registerNF = originalRegisterNF
				if keepAliveTimer != nil {
					keepAliveTimer.Stop()
				}
			}()

			consumer.SendDeregisterNFInstance = tc.sendDeregisterNFInstanceMock
			registerNF = func(ctx context.Context, newSessionManagementConfig []nfConfigApi.SessionManagement) {
				isRegisterNFCalled = true
			}

			ch := make(chan []nfConfigApi.SessionManagement, 1)
			ctx := t.Context()
			go StartNfRegistrationService(ctx, ch)
			ch <- []nfConfigApi.SessionManagement{}

			time.Sleep(100 * time.Millisecond)

			if keepAliveTimer != nil {
				t.Errorf("expected keepAliveTimer to be nil after stopKeepAliveTimer")
			}
			if !isDeregisterNFCalled {
				t.Errorf("expected SendDeregisterNFInstance to be called")
			}
			if isRegisterNFCalled {
				t.Errorf("expected registerNF not to be called")
			}
		})
	}
}

func TestNfRegistrationService_WhenConfigChanged_ThenRegisterNFSuccessAndStartTimer(t *testing.T) {
	keepAliveTimer = nil
	originalSendRegisterNFInstance := consumer.SendRegisterNFInstance
	defer func() {
		consumer.SendRegisterNFInstance = originalSendRegisterNFInstance
		if keepAliveTimer != nil {
			keepAliveTimer.Stop()
		}
	}()

	registrations := []nfConfigApi.SessionManagement{}
	consumer.SendRegisterNFInstance = func(sessionManagementConfig []nfConfigApi.SessionManagement) (models.NfProfile, string, error) {
		profile := models.NfProfile{HeartBeatTimer: 60}
		registrations = append(registrations, sessionManagementConfig...)
		return profile, "", nil
	}

	ch := make(chan []nfConfigApi.SessionManagement, 1)
	ctx := t.Context()
	go StartNfRegistrationService(ctx, ch)
	sessionConfigs = append(sessionConfigs, sessionConfigOne)
	newConfig := sessionConfigs
	ch <- newConfig

	time.Sleep(100 * time.Millisecond)
	if keepAliveTimer == nil {
		t.Error("expected keepAliveTimer to be initialized by startKeepAliveTimer")
	}
	if !reflect.DeepEqual(registrations, newConfig) {
		t.Errorf("expected %+v config, received %+v", newConfig, registrations)
	}
}

func TestNfRegistrationService_ConfigChanged_RetryIfRegisterNFFails(t *testing.T) {
	originalSendRegisterNFInstance := consumer.SendRegisterNFInstance
	defer func() {
		consumer.SendRegisterNFInstance = originalSendRegisterNFInstance
		if keepAliveTimer != nil {
			keepAliveTimer.Stop()
		}
	}()

	called := 0
	consumer.SendRegisterNFInstance = func(sessionManagementConfig []nfConfigApi.SessionManagement) (models.NfProfile, string, error) {
		profile := models.NfProfile{HeartBeatTimer: 60}
		called++
		return profile, "", errors.New("mock error")
	}

	ch := make(chan []nfConfigApi.SessionManagement, 1)
	ctx := t.Context()
	go StartNfRegistrationService(ctx, ch)
	sessionConfigs = append(sessionConfigs, sessionConfigOne)
	ch <- sessionConfigs

	time.Sleep(2 * retryTime)

	if called < 2 {
		t.Error("expected to retry register to NRF")
	}
	t.Logf("Tried %v times", called)
}

func TestNfRegistrationService_WhenConfigChanged_ThenRegistrationIsCancelled_IfConfigUsedInNFProfileIsUpdated_OtherwiseSameRegistrationUsed(t *testing.T) {
	originalRegisterNf := registerNF
	defer func() {
		registerNF = originalRegisterNf
		if keepAliveTimer != nil {
			keepAliveTimer.Stop()
		}
	}()

	var registrations []struct {
		ctx    context.Context
		config []nfConfigApi.SessionManagement
	}

	registerNF = func(registerCtx context.Context, newSessionManagementConfig []nfConfigApi.SessionManagement) {
		registrations = append(registrations, struct {
			ctx    context.Context
			config []nfConfigApi.SessionManagement
		}{registerCtx, newSessionManagementConfig})
		<-registerCtx.Done() // Wait until registration is cancelled
	}

	ch := make(chan []nfConfigApi.SessionManagement, 2)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go StartNfRegistrationService(ctx, ch)

	firstConfig, err := makeSessionConfig("sliceA", "001", "01", "1", "000001", "internet", "10.0.0.0/24", "upf1", 8805)
	if err != nil {
		t.Fatalf("failed to create first config: %v", err)
	}
	ch <- []nfConfigApi.SessionManagement{firstConfig}
	time.Sleep(50 * time.Millisecond)

	if len(registrations) != 1 {
		t.Fatalf("expected 1 registration, got %d", len(registrations))
	}

	secondConfig, err := makeSessionConfig("sliceA", "001", "09", "1", "000002", "internet", "10.0.0.0/24", "upf1", 8805)
	if err != nil {
		t.Fatalf("failed to create second config: %v", err)
	}
	ch <- []nfConfigApi.SessionManagement{secondConfig}
	time.Sleep(50 * time.Millisecond)

	if len(registrations) != 2 {
		t.Fatalf("expected 2 registrations, got %d", len(registrations))
	}

	thirdConfig, err := makeSessionConfig("sliceA", "001", "09", "1", "000002", "internet", "10.0.0.0/24", "upf1", 9905)
	if err != nil {
		t.Fatalf("failed to create third config: %v", err)
	}
	ch <- []nfConfigApi.SessionManagement{thirdConfig}
	time.Sleep(50 * time.Millisecond)

	if len(registrations) != 2 {
		t.Fatalf("expected 2 registrations, got %d", len(registrations))
	}

	select {
	case <-registrations[0].ctx.Done():
		// expected
	default:
		t.Error("expected first registration context to be cancelled")
	}

	select {
	case <-registrations[1].ctx.Done():
		t.Error("second registration context should not be cancelled")
	default:
		// expected
	}

	if !reflect.DeepEqual(registrations[0].config, []nfConfigApi.SessionManagement{firstConfig}) {
		t.Errorf("expected first config %+v, got %+v", firstConfig, registrations[0].config)
	}
	if !reflect.DeepEqual(registrations[1].config, []nfConfigApi.SessionManagement{secondConfig}) {
		t.Errorf("expected second config %+v, got %+v", secondConfig, registrations[1].config)
	}
}

func TestHeartbeatNF_Success(t *testing.T) {
	keepAliveTimer = time.NewTimer(60 * time.Second)
	calledRegister := false
	originalSendRegisterNFInstance := consumer.SendRegisterNFInstance
	originalSendUpdateNFInstance := consumer.SendUpdateNFInstance
	defer func() {
		consumer.SendRegisterNFInstance = originalSendRegisterNFInstance
		consumer.SendUpdateNFInstance = originalSendUpdateNFInstance
		if keepAliveTimer != nil {
			keepAliveTimer.Stop()
		}
	}()

	consumer.SendUpdateNFInstance = func(patchItem []models.PatchItem) (models.NfProfile, *models.ProblemDetails, error) {
		return models.NfProfile{}, nil, nil
	}
	consumer.SendRegisterNFInstance = func(sessionManagementConfig []nfConfigApi.SessionManagement) (models.NfProfile, string, error) {
		calledRegister = true
		profile := models.NfProfile{HeartBeatTimer: 60}
		return profile, "", nil
	}
	sessionManagementConfig := []nfConfigApi.SessionManagement{}
	heartbeatNF(sessionManagementConfig)

	if calledRegister {
		t.Errorf("expected registerNF to be called on error")
	}
	if keepAliveTimer == nil {
		t.Error("expected keepAliveTimer to be initialized by startKeepAliveTimer")
	}
}

func TestHeartbeatNF_WhenNfUpdateFails_ThenNfRegistersIsCalled(t *testing.T) {
	keepAliveTimer = time.NewTimer(60 * time.Second)
	calledRegister := false
	originalSendRegisterNFInstance := consumer.SendRegisterNFInstance
	originalSendUpdateNFInstance := consumer.SendUpdateNFInstance
	defer func() {
		consumer.SendRegisterNFInstance = originalSendRegisterNFInstance
		consumer.SendUpdateNFInstance = originalSendUpdateNFInstance
		if keepAliveTimer != nil {
			keepAliveTimer.Stop()
		}
	}()

	consumer.SendUpdateNFInstance = func(patchItem []models.PatchItem) (models.NfProfile, *models.ProblemDetails, error) {
		return models.NfProfile{}, nil, errors.New("mock error")
	}

	consumer.SendRegisterNFInstance = func(sessionManagementConfig []nfConfigApi.SessionManagement) (models.NfProfile, string, error) {
		profile := models.NfProfile{HeartBeatTimer: 60}
		calledRegister = true
		return profile, "", nil
	}

	sessionManagementConfig := []nfConfigApi.SessionManagement{}
	heartbeatNF(sessionManagementConfig)

	if !calledRegister {
		t.Errorf("expected registerNF to be called on error")
	}
	if keepAliveTimer == nil {
		t.Error("expected keepAliveTimer to be initialized by startKeepAliveTimer")
	}
}

func TestStartKeepAliveTimer_UsesProfileTimerOnlyWhenGreaterThanZero(t *testing.T) {
	testCases := []struct {
		name             string
		profileTime      int32
		expectedDuration time.Duration
	}{
		{
			name:             "Profile heartbeat time is zero, use default time",
			profileTime:      0,
			expectedDuration: 60 * time.Second,
		},
		{
			name:             "Profile heartbeat time is smaller than zero, use default time",
			profileTime:      -5,
			expectedDuration: 60 * time.Second,
		},
		{
			name:             "Profile heartbeat time is greater than zero, use profile time",
			profileTime:      15,
			expectedDuration: 15 * time.Second,
		},
		{
			name:             "Profile heartbeat time is greater than default time, use profile time",
			profileTime:      90,
			expectedDuration: 90 * time.Second,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			keepAliveTimer = time.NewTimer(25 * time.Second)
			defer func() {
				if keepAliveTimer != nil {
					keepAliveTimer.Stop()
				}
			}()
			var capturedDuration time.Duration

			afterFunc = func(d time.Duration, _ func()) *time.Timer {
				capturedDuration = d
				return time.NewTimer(25 * time.Second)
			}
			defer func() { afterFunc = time.AfterFunc }()

			startKeepAliveTimer(tc.profileTime, nil)
			if tc.expectedDuration != capturedDuration {
				t.Errorf("expected %v duration, got %v", tc.expectedDuration, capturedDuration)
			}
		})
	}
}
