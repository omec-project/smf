// Copyright 2024 Canonical Ltd.
//
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"fmt"
	"os"
	"testing"

	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/openapi/v2/utils"
	smfContext "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
)

var (
	nfInstanceID   = "34343-4343-43-434-343"
	subscriptionID = "46326-232353-2323"
)

func setupTest() {
	if err := factory.InitConfigFactory("../config/smfcfg.yaml"); err != nil {
		fmt.Printf("Could not InitConfigFactory: %+v", err)
	}
}

func TestNfSubscriptionStatusNotify(t *testing.T) {
	t.Logf("test cases fore NfSubscriptionStatusNotify")
	callCountSendRemoveSubscription := 0
	callCountNRFCacheRemoveNfProfileFromNrfCache := 0
	origSendRemoveSubscription := SendRemoveSubscription
	origNRFCacheRemoveNfProfileFromNrfCache := NRFCacheRemoveNfProfileFromNrfCache
	defer func() {
		SendRemoveSubscription = origSendRemoveSubscription
		NRFCacheRemoveNfProfileFromNrfCache = origNRFCacheRemoveNfProfileFromNrfCache
	}()
	SendRemoveSubscription = func(subscriptionId string) (problemDetails *models.ProblemDetails, err error) {
		t.Logf("test SendRemoveSubscription called")
		callCountSendRemoveSubscription++
		return nil, nil
	}
	NRFCacheRemoveNfProfileFromNrfCache = func(nfInstanceId string) bool {
		t.Logf("test NRFCacheRemoveNfProfileFromNrfCache called")
		callCountNRFCacheRemoveNfProfileFromNrfCache++
		return true
	}
	udmProfile := models.NewNotificationDataAllOfNfProfile(nfInstanceID, "UDM", "DEREGISTERED")
	udrInfo := models.UdrInfo{
		SupportedDataSets: []models.DataSetId{
			models.DATASETID_SUBSCRIPTION,
		},
	}
	udmProfile.SetUdrInfo(udrInfo)
	badRequestProblem := utils.ProblemDetailsMandatoryIeMissing("Missing IE [Event]/[NfInstanceUri] in NotificationData")
	parameters := []struct {
		expectedProblem                                      *models.ProblemDetails
		testName                                             string
		result                                               string
		nfInstanceId                                         string
		nfInstanceIdForSubscription                          string
		subscriptionID                                       string
		notificationEventType                                string
		expectedCallCountSendRemoveSubscription              int
		expectedCallCountNRFCacheRemoveNfProfileFromNrfCache int
		enableNrfCaching                                     bool
	}{
		{
			nil,
			"Notification event type DEREGISTERED NRF caching is enabled",
			"NF profile removed from cache and subscription is removed",
			nfInstanceID,
			nfInstanceID,
			subscriptionID,
			"NF_DEREGISTERED",
			1,
			1,
			true,
		},
		{
			nil,
			"Notification event type DEREGISTERED NRF caching is enabled Subscription is not found",
			"NF profile removed from cache and subscription is not removed",
			nfInstanceID,
			"",
			"",
			"NF_DEREGISTERED",
			0,
			1,
			true,
		},
		{
			nil,
			"Notification event type DEREGISTERED NRF caching is disabled",
			"NF profile is not removed from cache and subscription is removed",
			nfInstanceID,
			nfInstanceID,
			subscriptionID,
			"NF_DEREGISTERED",
			1,
			0,
			false,
		},
		{
			nil,
			"Notification event type REGISTERED NRF caching is enabled",
			"NF profile is not removed from cache and subscription is not removed",
			nfInstanceID,
			nfInstanceID,
			subscriptionID,
			"NF_REGISTERED",
			0,
			0,
			true,
		},
		{
			nil,
			"Notification event type DEREGISTERED NRF caching is enabled NfInstanceUri in notificationData is different",
			"NF profile removed from cache and subscription is not removed",
			nfInstanceID,
			nfInstanceID,
			subscriptionID,
			"NF_DEREGISTERED",
			1,
			1,
			true,
		},
		{
			badRequestProblem,
			"Notification event type DEREGISTERED NRF caching is enabled NfInstanceUri in notificationData is empty",
			"Return StatusBadRequest with cause MANDATORY_IE_MISSING",
			"",
			"",
			subscriptionID,
			"NF_DEREGISTERED",
			0,
			0,
			true,
		},
		{
			badRequestProblem,
			"Notification event type empty NRF caching is enabled",
			"Return StatusBadRequest with cause MANDATORY_IE_MISSING",
			nfInstanceID,
			nfInstanceID,
			subscriptionID,
			"",
			0,
			0,
			true,
		},
	}
	for i := range parameters {
		t.Run(fmt.Sprintf("NfSubscriptionStatusNotify testname %v result %v", parameters[i].testName, parameters[i].result), func(t *testing.T) {
			prevEnableNrfCaching := smfContext.SMF_Self().EnableNrfCaching
			smfContext.SMF_Self().EnableNrfCaching = parameters[i].enableNrfCaching
			smfContext.SMF_Self().NfStatusSubscriptions.Store(parameters[i].nfInstanceIdForSubscription, parameters[i].subscriptionID)
			t.Cleanup(func() {
				callCountSendRemoveSubscription = 0
				callCountNRFCacheRemoveNfProfileFromNrfCache = 0
				smfContext.SMF_Self().NfStatusSubscriptions.Delete(parameters[i].nfInstanceIdForSubscription)
				smfContext.SMF_Self().EnableNrfCaching = prevEnableNrfCaching
			})
			notificationData := models.NotificationData{
				Event:          models.NotificationEventType(parameters[i].notificationEventType),
				NfInstanceUri:  parameters[i].nfInstanceId,
				NfProfile:      udmProfile,
				ProfileChanges: []models.ChangeItem{},
			}
			err := NfSubscriptionStatusNotifyProcedure(notificationData)
			if parameters[i].expectedProblem == nil {
				if err != nil {
					t.Errorf("NfSubscriptionStatusNotifyProcedure error mismatch. got = %v, want = nil (NfSubscriptionStatusNotifyProcedure is failed)", err)
				}
			} else {
				if err == nil {
					t.Fatalf("NfSubscriptionStatusNotifyProcedure error mismatch. got = nil, want = %v (NfSubscriptionStatusNotifyProcedure is failed)", parameters[i].expectedProblem)
				}
				if err.GetStatus() != parameters[i].expectedProblem.GetStatus() ||
					err.GetCause() != parameters[i].expectedProblem.GetCause() ||
					err.GetTitle() != parameters[i].expectedProblem.GetTitle() ||
					err.GetDetail() != parameters[i].expectedProblem.GetDetail() {
					t.Errorf("NfSubscriptionStatusNotifyProcedure error mismatch. got status=%d cause=%q title=%q detail=%q, want status=%d cause=%q title=%q detail=%q (NfSubscriptionStatusNotifyProcedure is failed)",
						err.GetStatus(), err.GetCause(), err.GetTitle(), err.GetDetail(),
						parameters[i].expectedProblem.GetStatus(), parameters[i].expectedProblem.GetCause(), parameters[i].expectedProblem.GetTitle(), parameters[i].expectedProblem.GetDetail())
				}
			}
			if callCountSendRemoveSubscription != parameters[i].expectedCallCountSendRemoveSubscription {
				t.Errorf("Subscription removal count mismatch. got = %d, want = %d (Subscription is not removed)",
					callCountSendRemoveSubscription, parameters[i].expectedCallCountSendRemoveSubscription)
			}
			if callCountNRFCacheRemoveNfProfileFromNrfCache != parameters[i].expectedCallCountNRFCacheRemoveNfProfileFromNrfCache {
				t.Errorf("NF Profile cache removal count mismatch. got = %d, want = %d (NF Profile is not removed from NRF cache)",
					callCountNRFCacheRemoveNfProfileFromNrfCache, parameters[i].expectedCallCountNRFCacheRemoveNfProfileFromNrfCache)
			}
		})
	}
}

func TestMain(m *testing.M) {
	setupTest()
	exitVal := m.Run()
	os.Exit(exitVal)
}
