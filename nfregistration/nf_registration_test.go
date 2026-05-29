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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/omec-project/openapi/v2"
	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/openapi/v2/nfConfigApi"
	"github.com/omec-project/smf/consumer"
)

var (
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

func startRegistrationServiceForTest(t *testing.T, ch <-chan []nfConfigApi.SessionManagement) (context.CancelFunc, <-chan struct{}) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		StartNfRegistrationService(ctx, ch)
	}()
	return cancel, done
}

func waitForCondition(t *testing.T, timeout time.Duration, condition func() bool, errMessage string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal(errMessage)
}

func withKeepAliveTimerLock(f func()) {
	keepAliveTimerMutex.Lock()
	defer keepAliveTimerMutex.Unlock()
	f()
}

func TestNfRegistrationService_WhenEmptyConfig_ThenDeregisterNFAndStopTimer(t *testing.T) {
	testCases := []struct {
		name                         string
		sendDeregisterNFInstanceMock func(called chan<- struct{}) func() error
	}{
		{
			name: "Success",
			sendDeregisterNFInstanceMock: func(called chan<- struct{}) func() error {
				return func() error {
					select {
					case called <- struct{}{}:
					default:
					}
					return nil
				}
			},
		},
		{
			name: "ErrorInDeregisterNFInstance",
			sendDeregisterNFInstanceMock: func(called chan<- struct{}) func() error {
				return func() error {
					select {
					case called <- struct{}{}:
					default:
					}
					return errors.New("mock error")
				}
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			withKeepAliveTimerLock(func() {
				stopKeepAliveTimer()
				keepAliveTimer = time.NewTimer(60 * time.Second)
			})

			registerCalled := make(chan struct{}, 1)
			deregisterCalled := make(chan struct{}, 1)
			originalDeregisterNF := consumer.SendDeregisterNFInstance
			originalRegisterNF := registerNF
			ch := make(chan []nfConfigApi.SessionManagement, 1)
			cancel, done := startRegistrationServiceForTest(t, ch)
			defer func() {
				cancel()
				<-done
				consumer.SendDeregisterNFInstance = originalDeregisterNF
				registerNF = originalRegisterNF
				withKeepAliveTimerLock(func() {
					stopKeepAliveTimer()
				})
			}()

			consumer.SendDeregisterNFInstance = tc.sendDeregisterNFInstanceMock(deregisterCalled)
			registerNF = func(ctx context.Context, newSessionManagementConfig []nfConfigApi.SessionManagement) {
				select {
				case registerCalled <- struct{}{}:
				default:
				}
			}

			ch <- []nfConfigApi.SessionManagement{}

			select {
			case <-deregisterCalled:
			case <-time.After(500 * time.Millisecond):
				t.Fatal("expected SendDeregisterNFInstance to be called")
			}

			waitForCondition(t, 500*time.Millisecond, func() bool {
				isNil := false
				withKeepAliveTimerLock(func() {
					isNil = keepAliveTimer == nil
				})
				return isNil
			}, "expected keepAliveTimer to be nil after stopKeepAliveTimer")

			select {
			case <-registerCalled:
				t.Errorf("expected registerNF not to be called")
			default:
			}
		})
	}
}

func TestNfRegistrationService_WhenConfigChanged_ThenRegisterNFSuccessAndStartTimer(t *testing.T) {
	withKeepAliveTimerLock(func() {
		stopKeepAliveTimer()
	})
	originalSendRegisterNFInstance := consumer.SendRegisterNFInstance
	ch := make(chan []nfConfigApi.SessionManagement, 1)
	cancel, done := startRegistrationServiceForTest(t, ch)
	defer func() {
		cancel()
		<-done
		consumer.SendRegisterNFInstance = originalSendRegisterNFInstance
		withKeepAliveTimerLock(func() {
			stopKeepAliveTimer()
		})
	}()

	registrationMu := sync.Mutex{}
	registrations := []nfConfigApi.SessionManagement{}
	registerCalled := make(chan struct{}, 1)
	consumer.SendRegisterNFInstance = func(sessionManagementConfig []nfConfigApi.SessionManagement) (*models.NFProfile, string, error) {
		profile := models.NFProfile{HeartBeatTimer: openapi.PtrInt32(60)}
		registrationMu.Lock()
		registrations = append(registrations, sessionManagementConfig...)
		registrationMu.Unlock()
		select {
		case registerCalled <- struct{}{}:
		default:
		}
		return &profile, "", nil
	}

	newConfig := []nfConfigApi.SessionManagement{sessionConfigOne}
	ch <- newConfig

	select {
	case <-registerCalled:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("expected SendRegisterNFInstance to be called")
	}

	waitForCondition(t, 500*time.Millisecond, func() bool {
		isSet := false
		withKeepAliveTimerLock(func() {
			isSet = keepAliveTimer != nil
		})
		return isSet
	}, "expected keepAliveTimer to be initialized by startKeepAliveTimer")

	registrationMu.Lock()
	registered := append([]nfConfigApi.SessionManagement(nil), registrations...)
	registrationMu.Unlock()
	if !reflect.DeepEqual(registered, newConfig) {
		t.Errorf("expected %+v config, received %+v", newConfig, registered)
	}
}

func TestNfRegistrationService_ConfigChanged_RetryIfRegisterNFFails(t *testing.T) {
	orig := consumer.SendRegisterNFInstance
	ch := make(chan []nfConfigApi.SessionManagement, 1)
	cancel, done := startRegistrationServiceForTest(t, ch)
	var attempts atomic.Int32
	consumer.SendRegisterNFInstance = func(_ []nfConfigApi.SessionManagement) (*models.NFProfile, string, error) {
		attempts.Add(1)
		return &models.NFProfile{HeartBeatTimer: openapi.PtrInt32(60)}, "", errors.New("mock error")
	}
	defer func() {
		cancel()
		<-done
		consumer.SendRegisterNFInstance = orig
		withKeepAliveTimerLock(func() {
			stopKeepAliveTimer()
		})
	}()

	ch <- []nfConfigApi.SessionManagement{sessionConfigOne}

	waitForCondition(t, retryTime+3*time.Second, func() bool {
		return attempts.Load() >= 2
	}, "expected to retry register to NRF")

	if attempts.Load() < 2 {
		t.Errorf("expected at least 2 retry attempts, got %d", attempts.Load())
	}
}

func TestNfRegistrationService_WhenConfigChanged_ThenRegistrationIsCancelled_IfConfigUsedInNFProfileIsUpdated_OtherwiseSameRegistrationUsed(t *testing.T) {
	originalRegisterNf := registerNF
	ch := make(chan []nfConfigApi.SessionManagement, 2)
	cancel, done := startRegistrationServiceForTest(t, ch)
	defer func() {
		cancel()
		<-done
		registerNF = originalRegisterNf
		withKeepAliveTimerLock(func() {
			stopKeepAliveTimer()
		})
	}()

	type registrationCall struct {
		ctx    context.Context
		config []nfConfigApi.SessionManagement
	}
	registrations := make(chan registrationCall, 3)

	registerNF = func(registerCtx context.Context, newSessionManagementConfig []nfConfigApi.SessionManagement) {
		configCopy, err := deepCopySessionManagement(newSessionManagementConfig)
		if err != nil {
			return
		}
		registrations <- registrationCall{ctx: registerCtx, config: configCopy}
		<-registerCtx.Done() // Wait until registration is cancelled
	}

	firstConfig, err := makeSessionConfig("sliceA", "001", "01", "1", "000001", "internet", "10.0.0.0/24", "upf1", 8805)
	if err != nil {
		t.Fatalf("failed to create first config: %v", err)
	}
	ch <- []nfConfigApi.SessionManagement{firstConfig}

	var firstRegistration registrationCall
	select {
	case firstRegistration = <-registrations:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("expected 1 registration")
	}

	secondConfig, err := makeSessionConfig("sliceA", "001", "09", "1", "000002", "internet", "10.0.0.0/24", "upf1", 8805)
	if err != nil {
		t.Fatalf("failed to create second config: %v", err)
	}
	ch <- []nfConfigApi.SessionManagement{secondConfig}

	var secondRegistration registrationCall
	select {
	case secondRegistration = <-registrations:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("expected 2 registrations")
	}

	thirdConfig, err := makeSessionConfig("sliceA", "001", "09", "1", "000002", "internet", "10.0.0.0/24", "upf1", 9905)
	if err != nil {
		t.Fatalf("failed to create third config: %v", err)
	}
	ch <- []nfConfigApi.SessionManagement{thirdConfig}

	select {
	case extra := <-registrations:
		t.Fatalf("expected 2 registrations, got unexpected third registration %+v", extra)
	case <-time.After(200 * time.Millisecond):
		// expected
	}

	select {
	case <-firstRegistration.ctx.Done():
		// expected
	case <-time.After(500 * time.Millisecond):
		t.Error("expected first registration context to be cancelled")
	}

	select {
	case <-secondRegistration.ctx.Done():
		t.Error("second registration context should not be cancelled")
	default:
		// expected
	}

	if !reflect.DeepEqual(firstRegistration.config, []nfConfigApi.SessionManagement{firstConfig}) {
		t.Errorf("expected first config %+v, got %+v", firstConfig, firstRegistration.config)
	}
	if !reflect.DeepEqual(secondRegistration.config, []nfConfigApi.SessionManagement{secondConfig}) {
		t.Errorf("expected second config %+v, got %+v", secondConfig, secondRegistration.config)
	}
}

func TestHeartbeatNF_Success(t *testing.T) {
	withKeepAliveTimerLock(func() {
		stopKeepAliveTimer()
		keepAliveTimer = time.NewTimer(60 * time.Second)
	})
	calledRegister := false
	originalSendRegisterNFInstance := consumer.SendRegisterNFInstance
	originalSendUpdateNFInstance := consumer.SendUpdateNFInstance
	defer func() {
		consumer.SendRegisterNFInstance = originalSendRegisterNFInstance
		consumer.SendUpdateNFInstance = originalSendUpdateNFInstance
		withKeepAliveTimerLock(func() {
			stopKeepAliveTimer()
		})
	}()

	consumer.SendUpdateNFInstance = func(patchItem []models.PatchItem) (*models.NFProfile, *models.ProblemDetails, error) {
		return &models.NFProfile{}, nil, nil
	}
	consumer.SendRegisterNFInstance = func(sessionManagementConfig []nfConfigApi.SessionManagement) (*models.NFProfile, string, error) {
		calledRegister = true
		profile := models.NFProfile{HeartBeatTimer: openapi.PtrInt32(60)}
		return &profile, "", nil
	}
	sessionManagementConfig := []nfConfigApi.SessionManagement{}
	heartbeatNF(sessionManagementConfig)

	if calledRegister {
		t.Errorf("expected registerNF to be called on error")
	}
	keepAliveTimerStarted := false
	withKeepAliveTimerLock(func() {
		keepAliveTimerStarted = keepAliveTimer != nil
	})
	if !keepAliveTimerStarted {
		t.Error("expected keepAliveTimer to be initialized by startKeepAliveTimer")
	}
}

func TestHeartbeatNF_WhenNfUpdateFails_ThenNfRegistersIsCalled(t *testing.T) {
	withKeepAliveTimerLock(func() {
		stopKeepAliveTimer()
		keepAliveTimer = time.NewTimer(60 * time.Second)
	})
	calledRegister := false
	originalSendRegisterNFInstance := consumer.SendRegisterNFInstance
	originalSendUpdateNFInstance := consumer.SendUpdateNFInstance
	defer func() {
		consumer.SendRegisterNFInstance = originalSendRegisterNFInstance
		consumer.SendUpdateNFInstance = originalSendUpdateNFInstance
		withKeepAliveTimerLock(func() {
			stopKeepAliveTimer()
		})
	}()

	consumer.SendUpdateNFInstance = func(patchItem []models.PatchItem) (*models.NFProfile, *models.ProblemDetails, error) {
		return &models.NFProfile{}, nil, errors.New("mock error")
	}

	consumer.SendRegisterNFInstance = func(sessionManagementConfig []nfConfigApi.SessionManagement) (*models.NFProfile, string, error) {
		profile := models.NFProfile{HeartBeatTimer: openapi.PtrInt32(60)}
		calledRegister = true
		return &profile, "", nil
	}

	sessionManagementConfig := []nfConfigApi.SessionManagement{}
	heartbeatNF(sessionManagementConfig)

	if !calledRegister {
		t.Errorf("expected registerNF to be called on error")
	}
	keepAliveTimerStarted := false
	withKeepAliveTimerLock(func() {
		keepAliveTimerStarted = keepAliveTimer != nil
	})
	if !keepAliveTimerStarted {
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
			withKeepAliveTimerLock(func() {
				stopKeepAliveTimer()
				keepAliveTimer = time.NewTimer(25 * time.Second)
			})
			defer func() {
				withKeepAliveTimerLock(func() {
					stopKeepAliveTimer()
				})
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
