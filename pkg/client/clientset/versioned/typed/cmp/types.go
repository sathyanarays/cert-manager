package cmp

import "encoding/asn1"

type PKIBody uint

const (
	Ir       PKIBody = iota // [0]  CertReqMessages,            --Initialization Request
	Ip                      // [1]  CertRepMessage,             --Initialization Response
	Cr                      // [2]  CertReqMessages,            --Certification Request
	Pp                      // [3]  CertRepMessage,             --Certification Response
	P10cr                   // [4]  CertificationRequest,       --imported from // [PKCS10]
	Popdecc                 // [5]  POPODecKeyChallContent,     --pop Challenge
	Popdecr                 // [6]  POPODecKeyRespContent,      --pop Response
	Kur                     // [7]  CertReqMessages,            --Key Update Request
	Kup                     // [8]  CertRepMessage,             --Key Update Response
	Krr                     // [9]  CertReqMessages,            --Key Recovery Request
	Krp                     // [10] KeyRecRepContent,           --Key Recovery Response
	Rr                      // [11] RevReqContent,              --Revocation Request
	Rp                      // [12] RevRepContent,              --Revocation Response
	Ccr                     // [13] CertReqMessages,            --Cross-Cert. Request
	Ccp                     // [14] CertRepMessage,             --Cross-Cert. Response
	Ckuann                  // [15] CAKeyUpdAnnContent,         --CA Key Update Ann.
	Cann                    // [16] CertAnnContent,             --Certificate Ann.
	Rann                    // [17] RevAnnContent,              --Revocation Ann.
	Crlann                  // [18] CRLAnnContent,              --CRL Announcement
	Pkiconf                 // [19] PKIConfirmContent,          --Confirmation
	Nested                  // [20] NestedMessageContent,       --Nested Message
	Genm                    // [21] GenMsgContent,              --General Message
	Genp                    // [22] GenRepContent,              --General Response
	Error                   // [23] ErrorMsgContent,            --Error Message
	CertConf                // [24] CertConfirmContent,         --Certificate confirm
	PollReq                 // [25] PollReqContent,             --Polling request
	PollRep                 // [26] PollRepContent              --Polling response
)

type PKIStatus uint

const (
	Accepted               PKIStatus = iota // (0) you got exactly what you asked for
	GrantedWithMods                         // (1) you got something like what you asked for
	Rejection                               // (2) you don't get it, more information elsewhere in the message
	Waiting                                 // (3) the request body part has not yet been processed
	RevocationWarning                       // (4) this message contains a warning that a revocation is imminent
	RevocationNotification                  // (5) notification that a revocation has occurred
	KeyUpdateWarning                        // (6) update already done for the oldCertId specified in CertReqMsg
)

type cmpVersion uint

const (
	Cmp1999 cmpVersion = 1
	Cmp2000            = 2
	Cmp2021            = 3
)

type PKIProtection asn1.BitString
