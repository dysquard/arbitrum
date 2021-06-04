package fireblocks

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
)

type fireblocks struct {
	assetId    string
	baseUrl    string
	privateKey string
	apiKey     string
}

type CreateNewTransactionBody struct {
	AssetId         string                          `json:"assetId"`
	Source          TransferPeerPath                `json:"source"`
	Destination     DestinationTransferPeerPath     `json:"destination"`
	Amount          string                          `json:"amount"`
	Fee             string                          `json:"fee,omitempty"`
	GasPrice        string                          `json:"gasPrice,omitempty"`
	GasLimit        string                          `json:"gasLimit,omitempty"`
	NetworkFee      string                          `json:"networkFee,omitempty"`
	FeeLevel        string                          `json:"feeLevel,omitempty"`
	MaxFee          string                          `json:"maxFee,omitempty"`
	FailOnLowFee    bool                            `json:"failOnLowFee,omitempty"`
	Note            string                          `json:"note,omitempty"`
	Operation       string                          `json:"operation,omitempty"`
	CustomerRefId   string                          `json:"customerRefId,omitempty"`
	Destinations    []TransactionRequestDestination `json:"destinations,omitempty"`
	ExtraParameters TransactionExtraParameters      `json:"extraParameters"`
}

type TransactionExtraParameters struct {
	ContractCallData string `json:"contractCallData"`
}

type TransferPeerPath struct {
	Type string `json:"type"`
	Id   string `json:"id"`
}

type DestinationTransferPeerPath struct {
	Type           string         `json:"type"`
	Id             string         `json:"id"`
	OneTimeAddress OneTimeAddress `json:"oneTimeAddress,omitempty"`
}

type OneTimeAddress struct {
	Address string `json:"address"`
	Tag     string `json:"tag"`
}

type CreateTransactionResponse struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

type TransactionRequestDestination struct {
	Amount      string `json:"amount"`
	Destination string `json:"destination"`
}

func (fb fireblocks) New(assetId string, baseUrl string, privateKey string, apiKey string) fireblocks {
	return fireblocks{
		assetId:    assetId,
		baseUrl:    baseUrl,
		privateKey: privateKey,
		apiKey:     apiKey,
	}
}

func (fb fireblocks) CreateNewTransaction(sourceId string, destinationId string, callData string) (*CreateTransactionResponse, error) {

	body := &CreateNewTransactionBody{
		AssetId:         "ETH",
		Source:          TransferPeerPath{Type: "VAULT_ACCOUNT", Id: sourceId},
		Destination:     DestinationTransferPeerPath{Type: "EXTERNAL_WALLET", Id: destinationId},
		Amount:          "0",
		Operation:       "CONTRACT_CALL",
		ExtraParameters: TransactionExtraParameters{ContractCallData: callData},
	}

	json_data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	resp, err := fb.postRequest("/v1/transactions", json_data)
	if err != nil {
		return nil, err
	}

	var result CreateTransactionResponse
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return nil, err
	}

	return &result, err
}

func (fb fireblocks) postRequest(path string, body []byte) (*http.Response, error) {
	token, err := fb.signJWT(path, body)
	if err != nil {
		return nil, err
	}

	client := &http.Client{}
	req, err := http.NewRequest("POST", "application/json", bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	req.Header.Add("X-API-Key", fb.apiKey)
	req.Header.Add("Authorization", token)
	return client.Do(req)
}

func (fb fireblocks) signJWT(path string, body []byte) (string, error) {
	newPath := strings.Replace(path, "[", "%5B", -1)
	newPath = strings.Replace(newPath, "]", "%5D", -1)
	now := time.Now().Unix()
	bodyHash := sha256.Sum256(body)

	claims := fireblocksClaims{
		Uri:      newPath,
		Nonce:    rand.Int63(),
		Iat:      now,
		Exp:      now + 55,
		Sub:      fb.apiKey,
		BodyHash: hex.EncodeToString(bodyHash[:]),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	return token.SignedString(fb.privateKey)
}

type fireblocksClaims struct {
	Uri      string `json:"url"`
	Nonce    int64  `json:"nonce"`
	Iat      int64  `json:"iat"`
	Exp      int64  `json:"exp"`
	Sub      string `json:"sub"`
	BodyHash string `json:"bodyHash"`
	jwt.StandardClaims
}
