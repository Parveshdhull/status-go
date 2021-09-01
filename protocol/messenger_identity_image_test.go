package protocol

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v3"
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

func (s *MessengerProfilePictureHandlerSuite) TestE2eSendingReceivingProfilePicture() {
	profilePicShowSettings := map[string]accounts.ProfilePicturesShowToType{
		"ShowToContactsOnly": accounts.ProfilePicturesShowToContactsOnly,
		"ShowToEveryone":     accounts.ProfilePicturesShowToEveryone,
		"ShowToNone":         accounts.ProfilePicturesShowToNone,
	}

	profilePicViewSettings := map[string]accounts.ProfilePicturesVisibilityType{
		"ViewFromContactsOnly": accounts.ProfilePicturesVisibilityContactsOnly,
		"ViewFromEveryone":     accounts.ProfilePicturesVisibilityEveryone,
		"ViewFromNone":         accounts.ProfilePicturesVisibilityNone,
	}

	isContactFor := map[string][]bool{
		"alice": {true, false},
		"bob":   {true, false},
	}

	chatContexts := []chatContext{
		publicChat,
		privateChat,
	}

	// TODO Set option for testing between private and public chat types
	//  private types need to send and received Contact Code message with attached chat identity
	//  private types send large and thumbnail image payloads

	// TODO see if possible to push each test scenario into a go routine

	for _, cc := range chatContexts {
		for sn, ss := range profilePicShowSettings {
			for vn, vs := range profilePicViewSettings {
				for _, ac := range isContactFor["alice"] {
					for _, bc := range isContactFor["bob"] {
						s.SetupTest()
						s.logger.Info("testing with criteria:",
							zap.String("chat context type", string(cc)),
							zap.String("profile picture Show Settings", sn),
							zap.String("profile picture View Settings", vn),
							zap.Bool("bob in Alice's Contacts", ac),
							zap.Bool("alice in Bob's Contacts", bc),
						)

						expectPicture, err := resultExpected(ss, vs, ac, bc)
						s.logger.Debug("expect to receive a profile pic?",
							zap.Bool("result", expectPicture),
							zap.Error(err))

						// Store profile pictures
						iis := s.generateAndStoreIdentityImages(s.alice)

						err = s.alice.settings.SaveSetting("profile-pictures-show-to", ss)
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

						// Create chats
						var aChat *Chat
						switch cc {
						case publicChat:
							// Alice opens creates a public chat
							aChat = CreatePublicChat("status", s.alice.transport)
							err = s.alice.SaveChat(aChat)
							s.NoError(err)

							// Bob opens up the public chat and joins it
							bChat := CreatePublicChat("status", s.alice.transport)
							err = s.bob.SaveChat(bChat)
							s.NoError(err)

							_, err = s.bob.Join(bChat)
							s.NoError(err)
						case privateChat:
							aChat = CreateOneToOneChat(s.generateKeyUID(&s.bobKey.PublicKey), &s.bobKey.PublicKey, s.bob.transport)
							err = s.alice.SaveChat(aChat)
							s.NoError(err)

							_, err = s.alice.Join(aChat)
							s.NoError(err)

							bChat := CreateOneToOneChat(s.generateKeyUID(&s.aliceKey.PublicKey), &s.aliceKey.PublicKey, s.alice.transport)
							err = s.bob.SaveChat(bChat)
							s.NoError(err)

							_, err = s.bob.Join(bChat)
							s.NoError(err)

							err = s.alice.publishContactCode()
							s.NoError(err)
						default:
							s.Failf("unexpected chat context type", "%s", string(cc))
						}

						// Alice sends a message to the public chat
						message := buildTestMessage(*aChat)
						response, err := s.alice.SendChatMessage(context.Background(), message)
						s.NoError(err)
						s.NotNil(response)

						// Poll bob to see if he got the chatIdentity
						// Retrieve ChatIdentity
						var contacts []*Contact

						options := func(b *backoff.ExponentialBackOff) {
							b.MaxElapsedTime = 2 * time.Second
						}
						err = tt.RetryWithBackOff(func() error {

							response, err = s.bob.RetrieveAll()
							if err != nil {
								return err
							}

							contacts = response.Contacts

							if len(contacts) > 0 && len(contacts[0].Images) > 0 {
								s.logger.Debug("", zap.Any("contacts", contacts))
								return nil
							}

							return errors.New("no new contacts with images received")
						}, options)
						if expectPicture {
							s.NoError(err)
							s.NotNil(contacts)
						} else {
							s.EqualError(err, "no new contacts with images received")
							continue
						}

						// Check if alice's contact data with profile picture is there
						var contact *Contact
						for _, c := range contacts {
							if c.ID == s.generateKeyUID(&s.alice.identity.PublicKey) {
								contact = c
							}
						}
						s.NotNil(contact)

						// Check Alice's profile picture(s)
						switch cc {
						case publicChat:
							s.Len(contact.Images, 1)

							// Check if the result matches expectation
							for _, ii := range iis {
								if ii.Name == images.SmallDimName {
									s.Equal(ii.Payload, contact.Images[images.SmallDimName].Payload)
								}
							}
						}

						s.TearDownTest()
					}
				}
			}
		}
	}

	s.SetupTest()
}

func resultExpected(ss accounts.ProfilePicturesShowToType, vs accounts.ProfilePicturesVisibilityType, ac, bc bool) (bool, error) {
	switch ss {
	case accounts.ProfilePicturesShowToContactsOnly:
		if ac {
			return resultExpectedVS(vs, bc)
		}
		return false, nil
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
		return true, nil
	case accounts.ProfilePicturesVisibilityEveryone:
		return true, nil
	case accounts.ProfilePicturesVisibilityNone:
		return false, nil
	default:
		return false, errors.New("unknown ProfilePicturesVisibilityType")
	}
}
