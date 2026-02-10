package api

import (
	"context"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/rclone/rclone/backend/iclouddrive/srp"
	"github.com/rclone/rclone/fs/fshttp"
	"github.com/rclone/rclone/lib/rest"
)

// Session represents an iCloud session
type Session struct {
	SessionToken   string         `json:"session_token"`
	Scnt           string         `json:"scnt"`
	SessionID      string         `json:"session_id"`
	AccountCountry string         `json:"account_country"`
	TrustToken     string         `json:"trust_token"`
	ClientID       string         `json:"client_id"`
	Cookies        []*http.Cookie `json:"cookies"`
	AccountInfo    AccountInfo    `json:"account_info"`

	authAttributes string       `json:"-"`
	srv            *rest.Client `json:"-"`
}

// String returns the session as a string
// func (s *Session) String() string {
// 	jsession, _ := json.Marshal(s)
// 	return string(jsession)
// }

// Request makes a request
func (s *Session) Request(ctx context.Context, opts rest.Opts, request any, response any) (*http.Response, error) {
	resp, err := s.srv.CallJSON(ctx, &opts, &request, &response)
	if err != nil {
		return resp, err
	}
	s.storeHeaderValues(resp)
	return resp, nil
}

// Call makes the call and returns the http.Response
func (s *Session) Call(ctx context.Context, opts rest.Opts) (*http.Response, error) {
	resp, err := s.srv.Call(ctx, &opts)
	if err != nil {
		return resp, err
	}
	s.storeHeaderValues(resp)
	return resp, nil
}

func (s *Session) storeHeaderValues(resp *http.Response) {
	if val := resp.Header.Get("X-Apple-ID-Account-Country"); val != "" {
		s.AccountCountry = val
	}
	if val := resp.Header.Get("X-Apple-ID-Session-Id"); val != "" {
		s.SessionID = val
	}
	if val := resp.Header.Get("X-Apple-Session-Token"); val != "" {
		s.SessionToken = val
	}
	if val := resp.Header.Get("X-Apple-TwoSV-Trust-Token"); val != "" {
		s.TrustToken = val
	}
	if val := resp.Header.Get("X-Apple-Auth-Attributes"); val != "" {
		s.authAttributes = val
	}
	if val := resp.Header.Get("scnt"); val != "" {
		s.Scnt = val
	}
}

// Requires2FA returns true if the session requires 2FA
func (s *Session) Requires2FA() bool {
	return s.AccountInfo.DsInfo.HsaVersion == 2 && s.AccountInfo.HsaChallengeRequired
}

// SignIn signs in the session
func (s *Session) SignIn(ctx context.Context) error {
	headers := s.GetAuthHeaders(map[string]string{})

	opts := rest.Opts{
		Method: "GET",
		Path:   "/authorize/signin",
		Parameters: url.Values{
			"frame_id":      {headers["X-Apple-OAuth-State"]},
			"skVersion":     {"7"},
			"iframeId":      {headers["X-Apple-OAuth-State"]},
			"client_id":     {headers["X-Apple-Widget-Key"]},
			"response_type": {headers["X-Apple-OAuth-Response-Type"]},
			"redirect_uri":  {headers["X-Apple-OAuth-Redirect-URI"]},
			"response_mode": {headers["X-Apple-OAuth-Response-Mode"]},
			"state":         {headers["X-Apple-OAuth-State"]},
			"authVersion":   {"latest"},
		},
		RootURL: authEndpoint,
	}
	resp, err := s.Call(ctx, opts)
	if err == nil {
		s.Cookies = resp.Cookies()
	}

	return err
}

func (s *Session) SignInInit(ctx context.Context, appleID, password string) (*SignInProof, error) {
	params := srp.GetParams(2048)
	params.NoUserNameInX = true // this is required for Apple's implementation

	client := srp.NewSRPClient(params, nil)
	values := map[string]any{
		"a":           base64.StdEncoding.EncodeToString(client.GetABytes()),
		"accountName": appleID,
		"protocols":   []SignInProtocol{SignInProtocolS2K, SignInProtocolS2KFO},
	}

	body, err := IntoReader(values)
	if err != nil {
		return nil, err
	}

	opts := rest.Opts{
		Method:       "POST",
		Path:         "/signin/init",
		ExtraHeaders: s.GetAuthHeaders(map[string]string{}),
		RootURL:      authEndpoint,
		Body:         body,
	}

	var responseInfo *SignInInitResponse
	_, err = s.Request(ctx, opts, nil, &responseInfo)
	if err != nil {
		return nil, err
	}
	if !responseInfo.Protocol.Valid() {
		return nil, fmt.Errorf("unsupported signin protocol: %q", responseInfo.Protocol)
	}

	salt, err := base64.StdEncoding.DecodeString(responseInfo.Salt)
	if err != nil {
		return nil, err
	}

	b, err := base64.StdEncoding.DecodeString(responseInfo.B)
	if err != nil {
		return nil, err
	}

	encodedPassword, err := responseInfo.Protocol.EncodePassword(password)
	if err != nil {
		return nil, err
	}

	srpPassword, err := pbkdf2.Key(sha256.New, string(encodedPassword), salt, responseInfo.Iteration, 32)
	if err != nil {
		return nil, err
	}

	client.ProcessClientChallange([]byte(appleID), srpPassword, salt, b)

	return &SignInProof{
		C:  responseInfo.C,
		M1: client.M1,
		M2: client.M2,
	}, nil
}

// SignInComplete completes the sign-in process.
func (s *Session) SignInComplete(ctx context.Context, appleID string, proof SignInProof) (*http.Response, error) {
	values := map[string]any{
		"accountName": appleID,
		"c":           proof.C,
		"m1":          base64.StdEncoding.EncodeToString(proof.M1),
		"m2":          base64.StdEncoding.EncodeToString(proof.M2),
		"rememberMe":  true,
		"trustTokens": []string{},
	}

	body, err := IntoReader(values)
	if err != nil {
		return nil, err
	}

	opts := rest.Opts{
		Method: "POST",
		Path:   "/signin/complete",
		Parameters: url.Values{
			"isRememberMeEnabled": {"true"},
		},
		ExtraHeaders: s.GetAuthHeaders(map[string]string{
			"scnt":                    s.Scnt,
			"X-Apple-ID-Session-Id":   s.SessionID,
			"X-Apple-Auth-Attributes": s.authAttributes,
		}),
		RootURL: authEndpoint,
		Body:    body,
	}

	resp, err := s.Request(ctx, opts, nil, nil)
	if err != nil {
		return nil, err
	}
	return resp, err
}

// AuthWithToken authenticates the session
func (s *Session) AuthWithToken(ctx context.Context) error {
	values := map[string]any{
		"accountCountryCode": s.AccountCountry,
		"dsWebAuthToken":     s.SessionToken,
		"extended_login":     true,
		"trustToken":         s.TrustToken,
	}
	body, err := IntoReader(values)
	if err != nil {
		return err
	}
	opts := rest.Opts{
		Method:       "POST",
		Path:         "/accountLogin",
		ExtraHeaders: GetCommonHeaders(map[string]string{}),
		RootURL:      setupEndpoint,
		Body:         body,
	}

	resp, err := s.Request(ctx, opts, nil, &s.AccountInfo)
	if err == nil {
		s.Cookies = resp.Cookies()
	}

	return err
}

// Validate2FACode validates the 2FA code
func (s *Session) Validate2FACode(ctx context.Context, code string) error {
	values := map[string]any{"securityCode": map[string]string{"code": code}}
	body, err := IntoReader(values)
	if err != nil {
		return err
	}

	headers := s.GetAuthHeaders(map[string]string{})
	headers["scnt"] = s.Scnt
	headers["X-Apple-ID-Session-Id"] = s.SessionID

	opts := rest.Opts{
		Method:       "POST",
		Path:         "/verify/trusteddevice/securitycode",
		ExtraHeaders: headers,
		RootURL:      authEndpoint,
		Body:         body,
		NoResponse:   true,
	}

	_, err = s.Request(ctx, opts, nil, nil)
	if err == nil {
		if err := s.TrustSession(ctx); err != nil {
			return err
		}

		return nil
	}

	return fmt.Errorf("validate2FACode failed: %w", err)
}

// TrustSession trusts the session
func (s *Session) TrustSession(ctx context.Context) error {
	headers := s.GetAuthHeaders(map[string]string{})
	headers["scnt"] = s.Scnt
	headers["X-Apple-ID-Session-Id"] = s.SessionID

	opts := rest.Opts{
		Method:        "GET",
		Path:          "/2sv/trust",
		ExtraHeaders:  headers,
		RootURL:       authEndpoint,
		NoResponse:    true,
		ContentLength: common.Int64(0),
	}

	_, err := s.Request(ctx, opts, nil, nil)
	if err != nil {
		return fmt.Errorf("trustSession failed: %w", err)
	}

	return s.AuthWithToken(ctx)
}

// ValidateSession validates the session
func (s *Session) ValidateSession(ctx context.Context) error {
	opts := rest.Opts{
		Method:        "POST",
		Path:          "/validate",
		ExtraHeaders:  s.GetHeaders(map[string]string{}),
		RootURL:       setupEndpoint,
		ContentLength: common.Int64(0),
	}
	_, err := s.Request(ctx, opts, nil, &s.AccountInfo)
	if err != nil {
		return fmt.Errorf("validateSession failed: %w", err)
	}

	return nil
}

// GetAuthHeaders returns the authentication headers for the session.
//
// It takes an `overwrite` map[string]string parameter which allows
// overwriting the default headers. It returns a map[string]string.
func (s *Session) GetAuthHeaders(overwrite map[string]string) map[string]string {
	headers := map[string]string{
		"Accept":                           "application/json, text/javascript",
		"Content-Type":                     "application/json",
		"X-Apple-OAuth-Client-Id":          s.ClientID,
		"X-Apple-OAuth-Client-Type":        "firstPartyAuth",
		"X-Apple-OAuth-Redirect-URI":       "https://www.icloud.com",
		"X-Apple-OAuth-Require-Grant-Code": "true",
		"X-Apple-OAuth-Response-Mode":      "web_message",
		"X-Apple-OAuth-Response-Type":      "code",
		"X-Apple-OAuth-State":              s.ClientID,
		"X-Apple-Widget-Key":               s.ClientID,
		"X-Apple-Frame-Id":                 s.ClientID,
		"X-Apple-I-FD-Client-Info":         `{"U":"Mozilla/5.0 (X11; Linux x86_64; rv:147.0) Gecko/20100101 Firefox/147.0","L":"de","Z":"GMT+01:00","V":"1.1","F":""}`,
		"Origin":                           idmsaEndpoint,
		"Referer":                          fmt.Sprintf("%s/", idmsaEndpoint),
		"User-Agent":                       "Mozilla/5.0 (X11; Linux x86_64; rv:147.0) Gecko/20100101 Firefox/147.0",
	}
	headers["Cookie"] = s.GetCookieString()
	maps.Copy(headers, overwrite)
	return headers
}

// GetHeaders Gets the authentication headers required for a request
func (s *Session) GetHeaders(overwrite map[string]string) map[string]string {
	headers := GetCommonHeaders(map[string]string{})
	headers["Cookie"] = s.GetCookieString()
	maps.Copy(headers, overwrite)
	return headers
}

// GetCookieString returns the cookie header string for the session.
func (s *Session) GetCookieString() string {
	cookieHeader := ""
	// we only care about name and value.
	for _, cookie := range s.Cookies {
		cookieHeader = cookieHeader + cookie.Name + "=" + cookie.Value + ";"
	}
	return cookieHeader
}

// GetCommonHeaders generates common HTTP headers with optional overwrite.
func GetCommonHeaders(overwrite map[string]string) map[string]string {
	headers := map[string]string{
		"Content-Type": "application/json",
		"Origin":       baseEndpoint,
		"Referer":      fmt.Sprintf("%s/", baseEndpoint),
		"User-Agent":   "Mozilla/5.0 (X11; Linux x86_64; rv:147.0) Gecko/20100101 Firefox/147.0",
	}
	maps.Copy(headers, overwrite)
	return headers
}

// MergeCookies merges two slices of http.Cookies, ensuring no duplicates are added.
func MergeCookies(left []*http.Cookie, right []*http.Cookie) ([]*http.Cookie, error) {
	var hashes []string
	for _, cookie := range right {
		hashes = append(hashes, cookie.Raw)
	}
	for _, cookie := range left {
		if !slices.Contains(hashes, cookie.Raw) {
			right = append(right, cookie)
		}
	}
	return right, nil
}

// GetCookiesForDomain filters the provided cookies based on the domain of the given URL.
func GetCookiesForDomain(url *url.URL, cookies []*http.Cookie) ([]*http.Cookie, error) {
	var domainCookies []*http.Cookie
	for _, cookie := range cookies {
		if strings.HasSuffix(url.Host, cookie.Domain) {
			domainCookies = append(domainCookies, cookie)
		}
	}
	return domainCookies, nil
}

// NewSession creates a new Session instance with default values.
func NewSession() *Session {
	session := &Session{}
	session.srv = rest.NewClient(fshttp.NewClient(context.Background())).SetRoot(baseEndpoint)
	//session.ClientID = "auth-" + uuid.New().String()
	return session
}

// SignInInitResponse is the response of a sign-in init request.
type SignInInitResponse struct {
	Iteration int            `json:"iteration"`
	Salt      string         `json:"salt"`
	Protocol  SignInProtocol `json:"protocol"`
	B         string         `json:"b"`
	C         string         `json:"c"`
}

type SignInProof struct {
	C  string
	M1 []byte
	M2 []byte
}

type SignInProtocol string

const (
	SignInProtocolS2K   SignInProtocol = "s2k"
	SignInProtocolS2KFO SignInProtocol = "s2k_fo"
)

func (p SignInProtocol) Valid() bool {
	return p == SignInProtocolS2K || p == SignInProtocolS2KFO
}

func (p SignInProtocol) EncodePassword(password string) ([]byte, error) {
	passHash := sha256.Sum256([]byte(password))
	switch p {
	case SignInProtocolS2K:
		return passHash[:], nil
	case SignInProtocolS2KFO:
		return []byte(hex.EncodeToString(passHash[:])), nil
	default:
		return nil, fmt.Errorf("unsupported signin protocol: %q", p)
	}
}

// AccountInfo represents an account info
type AccountInfo struct {
	DsInfo                       *ValidateDataDsInfo    `json:"dsInfo"`
	HasMinimumDeviceForPhotosWeb bool                   `json:"hasMinimumDeviceForPhotosWeb"`
	ICDPEnabled                  bool                   `json:"iCDPEnabled"`
	Webservices                  map[string]*webService `json:"webservices"`
	PcsEnabled                   bool                   `json:"pcsEnabled"`
	TermsUpdateNeeded            bool                   `json:"termsUpdateNeeded"`
	ConfigBag                    struct {
		Urls struct {
			AccountCreateUI     string `json:"accountCreateUI"`
			AccountLoginUI      string `json:"accountLoginUI"`
			AccountLogin        string `json:"accountLogin"`
			AccountRepairUI     string `json:"accountRepairUI"`
			DownloadICloudTerms string `json:"downloadICloudTerms"`
			RepairDone          string `json:"repairDone"`
			AccountAuthorizeUI  string `json:"accountAuthorizeUI"`
			VettingURLForEmail  string `json:"vettingUrlForEmail"`
			AccountCreate       string `json:"accountCreate"`
			GetICloudTerms      string `json:"getICloudTerms"`
			VettingURLForPhone  string `json:"vettingUrlForPhone"`
		} `json:"urls"`
		AccountCreateEnabled bool `json:"accountCreateEnabled"`
	} `json:"configBag"`
	HsaTrustedBrowser            bool     `json:"hsaTrustedBrowser"`
	AppsOrder                    []string `json:"appsOrder"`
	Version                      int      `json:"version"`
	IsExtendedLogin              bool     `json:"isExtendedLogin"`
	PcsServiceIdentitiesIncluded bool     `json:"pcsServiceIdentitiesIncluded"`
	IsRepairNeeded               bool     `json:"isRepairNeeded"`
	HsaChallengeRequired         bool     `json:"hsaChallengeRequired"`
	RequestInfo                  struct {
		Country  string `json:"country"`
		TimeZone string `json:"timeZone"`
		Region   string `json:"region"`
	} `json:"requestInfo"`
	PcsDeleted bool `json:"pcsDeleted"`
	ICloudInfo struct {
		SafariBookmarksHasMigratedToCloudKit bool `json:"SafariBookmarksHasMigratedToCloudKit"`
	} `json:"iCloudInfo"`
	Apps map[string]*ValidateDataApp `json:"apps"`
}

// ValidateDataDsInfo represents an validation info
type ValidateDataDsInfo struct {
	HsaVersion                         int      `json:"hsaVersion"`
	LastName                           string   `json:"lastName"`
	ICDPEnabled                        bool     `json:"iCDPEnabled"`
	TantorMigrated                     bool     `json:"tantorMigrated"`
	Dsid                               string   `json:"dsid"`
	HsaEnabled                         bool     `json:"hsaEnabled"`
	IsHideMyEmailSubscriptionActive    bool     `json:"isHideMyEmailSubscriptionActive"`
	IroncadeMigrated                   bool     `json:"ironcadeMigrated"`
	Locale                             string   `json:"locale"`
	BrZoneConsolidated                 bool     `json:"brZoneConsolidated"`
	ICDRSCapableDeviceList             string   `json:"ICDRSCapableDeviceList"`
	IsManagedAppleID                   bool     `json:"isManagedAppleID"`
	IsCustomDomainsFeatureAvailable    bool     `json:"isCustomDomainsFeatureAvailable"`
	IsHideMyEmailFeatureAvailable      bool     `json:"isHideMyEmailFeatureAvailable"`
	ContinueOnDeviceEligibleDeviceInfo []string `json:"ContinueOnDeviceEligibleDeviceInfo"`
	Gilligvited                        bool     `json:"gilligvited"`
	AppleIDAliases                     []any    `json:"appleIdAliases"`
	UbiquityEOLEnabled                 bool     `json:"ubiquityEOLEnabled"`
	IsPaidDeveloper                    bool     `json:"isPaidDeveloper"`
	CountryCode                        string   `json:"countryCode"`
	NotificationID                     string   `json:"notificationId"`
	PrimaryEmailVerified               bool     `json:"primaryEmailVerified"`
	ADsID                              string   `json:"aDsID"`
	Locked                             bool     `json:"locked"`
	ICDRSCapableDeviceCount            int      `json:"ICDRSCapableDeviceCount"`
	HasICloudQualifyingDevice          bool     `json:"hasICloudQualifyingDevice"`
	PrimaryEmail                       string   `json:"primaryEmail"`
	AppleIDEntries                     []struct {
		IsPrimary bool   `json:"isPrimary"`
		Type      string `json:"type"`
		Value     string `json:"value"`
	} `json:"appleIdEntries"`
	GilliganEnabled    bool   `json:"gilligan-enabled"`
	IsWebAccessAllowed bool   `json:"isWebAccessAllowed"`
	FullName           string `json:"fullName"`
	MailFlags          struct {
		IsThreadingAvailable           bool `json:"isThreadingAvailable"`
		IsSearchV2Provisioned          bool `json:"isSearchV2Provisioned"`
		SCKMail                        bool `json:"sCKMail"`
		IsMppSupportedInCurrentCountry bool `json:"isMppSupportedInCurrentCountry"`
	} `json:"mailFlags"`
	LanguageCode         string `json:"languageCode"`
	AppleID              string `json:"appleId"`
	HasUnreleasedOS      bool   `json:"hasUnreleasedOS"`
	AnalyticsOptInStatus bool   `json:"analyticsOptInStatus"`
	FirstName            string `json:"firstName"`
	ICloudAppleIDAlias   string `json:"iCloudAppleIdAlias"`
	NotesMigrated        bool   `json:"notesMigrated"`
	BeneficiaryInfo      struct {
		IsBeneficiary bool `json:"isBeneficiary"`
	} `json:"beneficiaryInfo"`
	HasPaymentInfo bool   `json:"hasPaymentInfo"`
	PcsDelet       bool   `json:"pcsDelet"`
	AppleIDAlias   string `json:"appleIdAlias"`
	BrMigrated     bool   `json:"brMigrated"`
	StatusCode     int    `json:"statusCode"`
	FamilyEligible bool   `json:"familyEligible"`
}

// ValidateDataApp represents an app
type ValidateDataApp struct {
	CanLaunchWithOneFactor bool `json:"canLaunchWithOneFactor"`
	IsQualifiedForBeta     bool `json:"isQualifiedForBeta"`
}

// WebService represents a web service
type webService struct {
	PcsRequired bool   `json:"pcsRequired"`
	URL         string `json:"url"`
	UploadURL   string `json:"uploadUrl"`
	Status      string `json:"status"`
}
