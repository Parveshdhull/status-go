package protocol

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"

	gethbridge "github.com/status-im/status-go/eth-node/bridge/geth"
	"github.com/status-im/status-go/eth-node/crypto"
	"github.com/status-im/status-go/eth-node/types"
	"github.com/status-im/status-go/images"
	"github.com/status-im/status-go/multiaccounts"
	"github.com/status-im/status-go/multiaccounts/accounts"
	"github.com/status-im/status-go/protocol/protobuf"
	"github.com/status-im/status-go/protocol/tt"
	"github.com/status-im/status-go/waku"
)

func TestMessengerProfilePictureHandlerSuite(t *testing.T) {
	suite.Run(t, new(MessengerProfilePictureHandlerSuite))
}

type MessengerProfilePictureHandlerSuite struct {
	suite.Suite
	alice *Messenger // client instance of Messenger
	bob   *Messenger // server instance of Messenger

	aliceKey *ecdsa.PrivateKey // private key for the alice instance of Messenger
	bobKey   *ecdsa.PrivateKey // private key for the bob instance of Messenger

	// If one wants to send messages between different instances of Messenger,
	// a single Waku service should be shared.
	shh    types.Waku
	logger *zap.Logger
}

func (s *MessengerProfilePictureHandlerSuite) SetupTest() {
	var err error

	s.logger = tt.MustCreateTestLogger()

	// Setup Waku things
	config := waku.DefaultConfig
	config.MinimumAcceptedPoW = 0
	shh := waku.New(&config, s.logger)
	s.shh = gethbridge.NewGethWakuWrapper(shh)
	s.Require().NoError(shh.Start())

	// Generate private keys for Alice and Bob
	s.aliceKey, err = crypto.GenerateKey()
	s.Require().NoError(err)
	s.bobKey, err = crypto.GenerateKey()
	s.Require().NoError(err)

	// Generate Alice Messenger
	s.alice, err = newMessengerWithKey(s.shh, s.aliceKey, s.logger, []Option{})
	s.Require().NoError(err)
	_, err = s.alice.Start()
	s.Require().NoError(err)

	// Generate Bob Messenger
	s.bob, err = newMessengerWithKey(s.shh, s.bobKey, s.logger, []Option{})
	s.Require().NoError(err)
	_, err = s.bob.Start()
	s.Require().NoError(err)

	// Setup MultiAccount for Alice Messenger
	s.setupMultiAccount(s.alice)
}

func (s *MessengerProfilePictureHandlerSuite) TearDownTest() {
	// Shutdown messengers
	s.NoError(s.alice.Shutdown())
	s.alice = nil
	s.NoError(s.bob.Shutdown())
	s.bob = nil
	_ = s.logger.Sync()
}

func (s *MessengerProfilePictureHandlerSuite) generateKeyUID(publicKey *ecdsa.PublicKey) string {
	return types.EncodeHex(crypto.FromECDSAPub(publicKey))
}

func (s *MessengerProfilePictureHandlerSuite) setupMultiAccount(m *Messenger) {
	keyUID := s.generateKeyUID(&m.identity.PublicKey)
	m.account = &multiaccounts.Account{KeyUID: keyUID}

	err := m.multiAccounts.SaveAccount(multiaccounts.Account{Name: "string", KeyUID: keyUID})
	s.NoError(err)
}

func (s *MessengerProfilePictureHandlerSuite) generateAndStoreIdentityImages(m *Messenger) []*images.IdentityImage {
	keyUID := s.generateKeyUID(&m.identity.PublicKey)
	iis := images.SampleIdentityImages()
	s.Require().NoError(m.multiAccounts.StoreIdentityImages(keyUID, iis))

	return iis
}

func (s *MessengerProfilePictureHandlerSuite) TestChatIdentity() {
	iis := s.generateAndStoreIdentityImages(s.alice)
	ci, err := s.alice.createChatIdentity(privateChat)
	s.Require().NoError(err)
	s.Require().Exactly(len(iis), len(ci.Images))
}

func (s *MessengerProfilePictureHandlerSuite) TestEncryptDecryptIdentityImagesWithContactPubKeys() {
	smPayload := "hello small image"
	lgPayload := "hello large image"

	ci := protobuf.ChatIdentity{
		Clock: uint64(time.Now().Unix()),
		Images: map[string]*protobuf.IdentityImage{
			"small": {
				Payload: []byte(smPayload),
			},
			"large": {
				Payload: []byte(lgPayload),
			},
		},
	}

	// Make contact keys and Contacts, set the Contacts to added
	contactKeys := make([]*ecdsa.PrivateKey, 10)
	for i := range contactKeys {
		contactKey, err := crypto.GenerateKey()
		s.Require().NoError(err)
		contactKeys[i] = contactKey

		contact, err := BuildContactFromPublicKey(&contactKey.PublicKey)
		s.Require().NoError(err)

		contact.SystemTags = append(contact.SystemTags, contactAdded)
		s.alice.allContacts.Store(contact.ID, contact)
	}

	// Test EncryptIdentityImagesWithContactPubKeys
	err := EncryptIdentityImagesWithContactPubKeys(ci.Images, s.alice)
	s.Require().NoError(err)

	for _, ii := range ci.Images {
		s.Require().Equal(s.alice.allContacts.Len(), len(ii.EncryptionKeys))
	}
	s.Require().NotEqual([]byte(smPayload), ci.Images["small"].Payload)
	s.Require().NotEqual([]byte(lgPayload), ci.Images["large"].Payload)
	s.Require().True(ci.Images["small"].Encrypted)
	s.Require().True(ci.Images["large"].Encrypted)

	// Test DecryptIdentityImagesWithIdentityPrivateKey
	err = DecryptIdentityImagesWithIdentityPrivateKey(ci.Images, contactKeys[2], &s.alice.identity.PublicKey)
	s.Require().NoError(err)

	s.Require().Equal(smPayload, string(ci.Images["small"].Payload))
	s.Require().Equal(lgPayload, string(ci.Images["large"].Payload))
	s.Require().False(ci.Images["small"].Encrypted)
	s.Require().False(ci.Images["large"].Encrypted)

	// RESET Messenger identity, Contacts and IdentityImage.EncryptionKeys
	s.alice.allContacts = new(contactMap)
	ci.Images["small"].EncryptionKeys = nil
	ci.Images["large"].EncryptionKeys = nil

	// Test EncryptIdentityImagesWithContactPubKeys with no contacts
	err = EncryptIdentityImagesWithContactPubKeys(ci.Images, s.alice)
	s.Require().NoError(err)

	for _, ii := range ci.Images {
		s.Require().Equal(0, len(ii.EncryptionKeys))
	}
	s.Require().NotEqual([]byte(smPayload), ci.Images["small"].Payload)
	s.Require().NotEqual([]byte(lgPayload), ci.Images["large"].Payload)
	s.Require().True(ci.Images["small"].Encrypted)
	s.Require().True(ci.Images["large"].Encrypted)

	// Test DecryptIdentityImagesWithIdentityPrivateKey with no valid identity
	err = DecryptIdentityImagesWithIdentityPrivateKey(ci.Images, contactKeys[2], &s.alice.identity.PublicKey)
	s.Require().NoError(err)

	s.Require().NotEqual([]byte(smPayload), ci.Images["small"].Payload)
	s.Require().NotEqual([]byte(lgPayload), ci.Images["large"].Payload)
	s.Require().True(ci.Images["small"].Encrypted)
	s.Require().True(ci.Images["large"].Encrypted)
}

func (s *MessengerProfilePictureHandlerSuite) TestSendingReceivingProfilePicture() {
	profilePicShowSettings := []accounts.ProfilePicturesShowToType{
		accounts.ProfilePicturesShowToContactsOnly,
		accounts.ProfilePicturesShowToEveryone,
		accounts.ProfilePicturesShowToNone,
	}

	profilePicViewSettings := []accounts.ProfilePicturesVisibilityType{
		accounts.ProfilePicturesVisibilityContactsOnly,
		accounts.ProfilePicturesVisibilityEveryone,
		accounts.ProfilePicturesVisibilityNone,
	}

	isContact := map[string][]bool{
		"alice": {true, false},
		"bob":   {true, false},
	}

	for _, ss := range profilePicShowSettings {
		for _, vs := range profilePicViewSettings {
			for _, ac := range isContact["alice"] {
				for _, bc := range isContact["bob"] {
					s.SetupTest()

					// Store profile pictures
					iis := s.generateAndStoreIdentityImages(s.alice)

					err := s.alice.settings.SaveSetting("profile-pictures-show-to", ss)
					s.NoError(err)

					err = s.bob.settings.SaveSetting("profile-pictures-visibility", vs)
					s.NoError(err)

					if ac {
						_, err = s.alice.AddContact(context.Background(), s.generateKeyUID(&s.bob.identity.PublicKey))
						s.NoError(err)
					}

					if bc {
						_, err = s.bob.AddContact(context.Background(), s.generateKeyUID(&s.alice.identity.PublicKey))
						s.NoError(err)
					}

					// TODO trigger sending chatIdentity via 1-1 chat

					// todo Poll bob to see if he got the chatIdentity

					// todo Check if alice's profile picture is there

					// todo check if the result matches expectation

					s.TearDownTest()
				}
			}
		}
	}

}

func resultExpected(ss accounts.ProfilePicturesShowToType, vs accounts.ProfilePicturesVisibilityType, ac, bc bool) (bool, error) {
	switch ss {
	case accounts.ProfilePicturesShowToContactsOnly:
		if ac {
			return resultExpectedVS(vs, bc)
		}
		return true, nil
	case accounts.ProfilePicturesShowToEveryone:
		return resultExpectedVS(vs, bc)
	case accounts.ProfilePicturesShowToNone:
		return false, nil
	default:
		return false, errors.New("unknown ProfilePicturesShowToType")
	}
}

func resultExpectedVS(vs accounts.ProfilePicturesVisibilityType, bc bool) (bool, error) {
	switch vs {
	case accounts.ProfilePicturesVisibilityContactsOnly:
		return bc, nil
	case accounts.ProfilePicturesVisibilityEveryone:
		return true, nil
	case accounts.ProfilePicturesVisibilityNone:
		return false, nil
	default:
		return false, errors.New("unknown ProfilePicturesVisibilityType")
	}
}
