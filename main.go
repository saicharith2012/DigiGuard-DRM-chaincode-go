package main

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

type DRM struct {
	contractapi.Contract
}

const (
	originOwner    = "originOwnerPlaceholder"
	collectionName = "privateCollection"
)

type User struct {
	Name          string   `json:"name"`
	Id            string   `json:"id"`
	Tel           string   `json:"tel"`
	Gender        string   `json:"gender"`
	Address       string   `json:"address"`
	Password      string   `json:"password"`
	Digitalrights []string `json:"digitalrights"`
}

type Digitalright struct {
	Name     string `json:"name"`
	Id       string `json:"id"`
	Type     string `json:"type"`
	Time     string `json:"time"`
	OwnerId  string `json:"ownerId"`
	Metadata string `json:"metadata"` // Previous metadata field
	IPFSHash string `json:"ipfsHash"` // New field for IPFS hash
}

type DigitalrightResponse struct {
	Digitalright *Digitalright `json:"digitalright"`
	OwnerId      string        `json:"ownerId"`
	OwnerName    string        `json:"ownerName"`
}

type DigitalrightHistory struct {
	DigitalrightId string `json:"digitalright_id"`
	OriginOwnerId  string `json:"origin_owner_id"`
	CurrentOwnerId string `json:"current_owner_id"`
	Time           string `json:"time"`
}

func constructUserKey(userId string) string {
	return fmt.Sprintf("user_%s", userId)
}

func constructDigitalrightKey(digitalrightId string) string {
	return fmt.Sprintf("digitalright_%s", digitalrightId)
}

// UserRegister function
// @Transaction
func (c *DRM) UserRegisterTransaction(ctx contractapi.TransactionContextInterface, name string, id string, tel string, gender string, address string, password string) error {
	// Validate arguments
	if name == "" || id == "" || password == "" {
		return fmt.Errorf("invalid args")
	}

	// Check if user already exists
	userBytes, err := ctx.GetStub().GetState(constructUserKey(id))
	if err == nil && len(userBytes) != 0 {
		return fmt.Errorf("user already exists")
	}

	// Create a new User object
	user := &User{
		Name:          name,
		Id:            id,
		Tel:           tel,
		Gender:        gender,
		Address:       address,
		Password:      password,
		Digitalrights: make([]string, 0),
	}

	// Marshal the user object into bytes
	userBytes, err = json.Marshal(user)
	if err != nil {
		return fmt.Errorf("marshal user error: %s", err)
	}

	// Store the user object in the ledger
	err = ctx.GetStub().PutState(constructUserKey(id), userBytes)
	if err != nil {
		return fmt.Errorf("put user error: %s", err)
	}

	return nil
}

// User destroy function
// @Transaction
func (c *DRM) UserDestroyTransaction(ctx contractapi.TransactionContextInterface, id string) error {
	// Validate the user ID
	if id == "" {
		return fmt.Errorf("invalid args")
	}

	// Get the user's data from the ledger
	userBytes, err := ctx.GetStub().GetState(constructUserKey(id))
	if err != nil || len(userBytes) == 0 {
		return fmt.Errorf("user not found")
	}

	// Delete the user's data from the ledger
	err = ctx.GetStub().DelState(constructUserKey(id))
	if err != nil {
		return fmt.Errorf("delete user error: %s", err)
	}

	// Unmarshal the user data
	user := new(User)
	if err := json.Unmarshal(userBytes, user); err != nil {
		return fmt.Errorf("unmarshal user error: %s", err)
	}

	// Iterate through the user's digital rights and delete them from the ledger
	for _, digitalrightID := range user.Digitalrights {
		err := ctx.GetStub().DelState(constructDigitalrightKey(digitalrightID))
		if err != nil {
			return fmt.Errorf("delete digitalright error: %s", err)
		}
	}

	return nil
}

// DigitalrightEnrollTransaction enrolls a new digital right in the blockchain ledger.
// This function is a transaction that creates a new digital right, associates it with an owner, and records the transaction history.
// ctx - The transaction context
// digitalrightName - Name of the digital right
// digitalrightId - ID of the digital right
// digitalrightType - Type of the digital right
// time - Timestamp of the enrollment
// metadata - Metadata associated with the digital right
// ownerId - ID of the owner of the digital right
// ipfsHash - IPFS hash of the digital right's content
// @return error - Error if any

// @Transaction
func (c *DRM) DigitalrightEnrollTransaction(ctx contractapi.TransactionContextInterface, digitalrightName string, digitalrightId string, digitalrightType string, time string, metadata string, ownerId string, ipfsHash string) error {
	// Validate arguments
	if digitalrightName == "" || digitalrightId == "" || digitalrightType == "" || metadata == "" || ownerId == "" || ipfsHash == "" {
		return fmt.Errorf("invalid args")
	}

	// Get the owner's data from the ledger
	userBytes, err := ctx.GetStub().GetState(constructUserKey(ownerId))
	if err != nil || len(userBytes) == 0 {
		return fmt.Errorf("user not found")
	}

	// Check if the digital right already exists
	digitalrightBytes, err := ctx.GetStub().GetState(constructDigitalrightKey(digitalrightId))
	if err == nil && len(digitalrightBytes) != 0 {
		return fmt.Errorf("digitalright already exists")
	}

	// Check if the IPFS hash is unique
	hashBytes, err := ctx.GetStub().GetPrivateData(collectionName, constructDigitalrightKey(ipfsHash))
	if err == nil && len(hashBytes) != 0 {
		return fmt.Errorf("IPFS hash already exists")
	}

	// Create a new Digitalright object
	digitalright := &Digitalright{
		Name:     digitalrightName,
		Id:       digitalrightId,
		Type:     digitalrightType,
		Time:     time,
		Metadata: metadata,
		OwnerId:  ownerId,
		IPFSHash: ipfsHash,
	}

	// Marshal the digital right object into bytes
	digitalrightBytes, err = json.Marshal(digitalright)
	if err != nil {
		return fmt.Errorf("marshal digitalright error: %s", err)
	}

	// Store the digital right object in the public ledger
	err = ctx.GetStub().PutState(constructDigitalrightKey(digitalrightId), digitalrightBytes)
	if err != nil {
		return fmt.Errorf("save digitalright error: %s", err)
	}

	// For the IPFS hash, use PutPrivateData to store it in the private data collection
	err = ctx.GetStub().PutPrivateData(collectionName, constructDigitalrightKey(ipfsHash), []byte(digitalrightId))
	if err != nil {
		return fmt.Errorf("save IPFS hash error: %s", err)
	}

	// Update the user's digital rights
	user := new(User)
	if err := json.Unmarshal(userBytes, user); err != nil {
		return fmt.Errorf("unmarshal user error: %s", err)
	}
	user.Digitalrights = append(user.Digitalrights, digitalrightId)

	// Marshal the updated user object into bytes
	userBytes, err = json.Marshal(user)
	if err != nil {
		return fmt.Errorf("marshal user error: %s", err)
	}

	// Update the user's data in the ledger
	err = ctx.GetStub().PutState(constructUserKey(user.Id), userBytes)
	if err != nil {
		return fmt.Errorf("update user error: %s", err)
	}

	// Create a DigitalrightHistory object
	history := &DigitalrightHistory{
		DigitalrightId: digitalrightId,
		OriginOwnerId:  ownerId,
		CurrentOwnerId: ownerId,
		Time:           time,
	}

	// Marshal the history object into bytes
	historyBytes, err := json.Marshal(history)
	if err != nil {
		return fmt.Errorf("marshal digitalright history error: %s", err)
	}

	// Create a composite key for the history object
	historyKey, err := ctx.GetStub().CreateCompositeKey("history", []string{
		digitalrightId,
		ownerId,
		ownerId,
		time,
	})

	if err != nil {
		return fmt.Errorf("create key error: %s", err)
	}

	// Store the history object in the ledger
	if err := ctx.GetStub().PutState(historyKey, historyBytes); err != nil {
		return fmt.Errorf("save digitalright history error: %s", err)
	}

	return nil
}

// DigitalrightExchangeTransaction performs the exchange of a digital right between two owners.
// This function updates the ownership and transaction history of the digital right.
// ctx - The transaction context
// ownerId - ID of the original owner
// digitalrightId - ID of the digital right being exchanged
// currentOwnerId - ID of the new owner
// time - Timestamp of the exchange
// @return error - Error if any

// @Transaction
func (c *DRM) DigitalrightExchangeTransaction(
	ctx contractapi.TransactionContextInterface,
	ownerId string,
	digitalrightId string,
	currentOwnerId string,
	time string,
) error {
	// Validate arguments
	if ownerId == "" || digitalrightId == "" || currentOwnerId == "" || time == "" {
		return fmt.Errorf("invalid args")
	}

	// Get the data of the original owner from the ledger
	originOwnerBytes, err := ctx.GetStub().GetState(constructUserKey(ownerId))
	if err != nil || len(originOwnerBytes) == 0 {
		return fmt.Errorf("original owner not found")
	}

	// Get the data of the current owner from the ledger
	currentOwnerBytes, err := ctx.GetStub().GetState(constructUserKey(currentOwnerId))
	if err != nil || len(currentOwnerBytes) == 0 {
		return fmt.Errorf("current owner not found")
	}

	// Get the data of the digital right from the ledger
	digitalrightBytes, err := ctx.GetStub().GetState(constructDigitalrightKey(digitalrightId))
	if err != nil || len(digitalrightBytes) == 0 {
		return fmt.Errorf("digitalright not found")
	}

	// Unmarshal the original owner's data
	originOwner := new(User)
	if err := json.Unmarshal(originOwnerBytes, originOwner); err != nil {
		return fmt.Errorf("unmarshal original owner error: %s", err)
	}

	// Check if the digital right belongs to the original owner
	aidExist := false
	for _, aid := range originOwner.Digitalrights {
		if aid == digitalrightId {
			aidExist = true
			break
		}
	}
	if !aidExist {
		return fmt.Errorf("digitalright owner not match")
	}

	// Update the original owner's digital rights by removing the exchanged digital right
	digitalrightIds := make([]string, 0)
	for _, aid := range originOwner.Digitalrights {
		if aid == digitalrightId {
			continue
		}
		digitalrightIds = append(digitalrightIds, aid)
	}
	originOwner.Digitalrights = digitalrightIds

	// Marshal the updated original owner object
	originOwnerBytes, err = json.Marshal(originOwner)
	if err != nil {
		return fmt.Errorf("marshal original owner error: %s", err)
	}

	// Update the original owner's data in the ledger
	err = ctx.GetStub().PutState(constructUserKey(ownerId), originOwnerBytes)
	if err != nil {
		return fmt.Errorf("update original owner error: %s", err)
	}

	// Unmarshal the current owner's data
	currentOwner := new(User)
	if err := json.Unmarshal(currentOwnerBytes, currentOwner); err != nil {
		return fmt.Errorf("unmarshal current owner error: %s", err)
	}

	// Add the exchanged digital right to the current owner's digital rights
	currentOwner.Digitalrights = append(currentOwner.Digitalrights, digitalrightId)

	// Marshal the updated current owner object
	currentOwnerBytes, err = json.Marshal(currentOwner)
	if err != nil {
		return fmt.Errorf("marshal current owner error: %s", err)
	}

	// Update the current owner's data in the ledger
	err = ctx.GetStub().PutState(constructUserKey(currentOwnerId), currentOwnerBytes)
	if err != nil {
		return fmt.Errorf("update current owner error: %s", err)
	}

	// Create a DigitalrightHistory object
	history := &DigitalrightHistory{
		DigitalrightId: digitalrightId,
		OriginOwnerId:  ownerId,
		CurrentOwnerId: currentOwnerId,
		Time:           time,
	}

	// Marshal the history object into bytes
	historyBytes, err := json.Marshal(history)
	if err != nil {
		return fmt.Errorf("marshal digitalright history error: %s", err)
	}

	// Create a composite key for the history object
	historyKey, err := ctx.GetStub().CreateCompositeKey("history", []string{
		digitalrightId,
		ownerId,
		currentOwnerId,
		time,
	})
	if err != nil {
		return fmt.Errorf("create key error: %s", err)
	}

	// Store the history object in the ledger
	if err := ctx.GetStub().PutState(historyKey, historyBytes); err != nil {
		return fmt.Errorf("save digitalright history error: %s", err)
	}

	return nil
}

// UserId should be provided as the argument
// @Transaction(false)
func (c *DRM) QueryUserTransaction(ctx contractapi.TransactionContextInterface, userId string) (*User, error) {
	userBytes, err := ctx.GetStub().GetState(constructUserKey(userId))
	if err != nil || len(userBytes) == 0 {
		return nil, fmt.Errorf("user not found")
	}

	user := new(User)
	if err := json.Unmarshal(userBytes, user); err != nil {
		return nil, fmt.Errorf("unmarshal user error: %s", err)
	}

	return user, nil
}

// QueryDigitalrightTransaction queries information about a digital right.
// Args:
// - digitalrightId: The ID of the digital right to query.
// Returns:
// - JSON representation of the digital right's details and its owner's information.

// @Transaction(false)
func (c *DRM) QueryDigitalrightTransaction(ctx contractapi.TransactionContextInterface, digitalrightID string) (*DigitalrightResponse, error) {
	// Get the digital right data from the ledger
	digitalrightBytes, err := ctx.GetStub().GetState(constructDigitalrightKey(digitalrightID))
	if err != nil || len(digitalrightBytes) == 0 {
		return nil, fmt.Errorf("digitalright not found")
	}

	// Unmarshal the digital right data
	digitalright := new(Digitalright)
	if err := json.Unmarshal(digitalrightBytes, digitalright); err != nil {
		return nil, fmt.Errorf("unmarshal digitalright error: %s", err)
	}

	// Exclude the ipfsHash field from the digitalright object
	digitalrightWithoutIPFS := &Digitalright{
		Name:     digitalright.Name,
		Id:       digitalright.Id,
		Type:     digitalright.Type,
		Time:     digitalright.Time,
		OwnerId:  digitalright.OwnerId,
		Metadata: digitalright.Metadata,
	}

	// Get the owner's data from the ledger
	ownerBytes, err := ctx.GetStub().GetState(constructUserKey(digitalright.OwnerId))
	if err != nil || len(ownerBytes) == 0 {
		return nil, fmt.Errorf("owner not found")
	}

	// Unmarshal the owner's data
	owner := new(User)
	if err := json.Unmarshal(ownerBytes, owner); err != nil {
		return nil, fmt.Errorf("unmarshal owner error: %s", err)
	}

	// Create a DigitalrightResponse object without the ipfsHash field
	response := &DigitalrightResponse{
		Digitalright: digitalrightWithoutIPFS,
		OwnerId:      owner.Id,
		OwnerName:    owner.Name,
	}

	return response, nil
}

// QueryDigitalrightHistoryTransaction queries the history of a digital right.
// Args:
// - digitalrightId: The ID of the digital right to query history for.
// - queryType: The type of history to query (all/enroll/exchange).
// Returns:
// - JSON representation of the digital right's history records based on the query type.

// @Transaction(false)
func (c *DRM) QueryDigitalrightHistoryTransaction(ctx contractapi.TransactionContextInterface, digitalrightId string, queryType string) ([]*DigitalrightHistory, error) {
	// Validate input
	if digitalrightId == "" || (queryType != "all" && queryType != "enroll" && queryType != "exchange") {
		return nil, fmt.Errorf("invalid arguments")
	}

	// Create keys for querying the history
	keys := []string{digitalrightId}
	switch queryType {
	case "enroll":
		keys = append(keys, originOwner)
	case "exchange", "all":
	default:
		return nil, fmt.Errorf("unsupported queryType")
	}

	// Get the history records based on the keys
	resultsIterator, err := ctx.GetStub().GetStateByPartialCompositeKey("history", keys)
	if err != nil {
		return nil, fmt.Errorf("query history error: %s", err)
	}
	defer resultsIterator.Close()

	// Create a slice to store history records
	histories := make([]*DigitalrightHistory, 0)
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, fmt.Errorf("query error: %s", err)
		}

		// Extract the value from the QueryResponse
		historyBytes := queryResponse.Value

		// Unmarshal the history data
		history := new(DigitalrightHistory)
		if err := json.Unmarshal(historyBytes, history); err != nil {
			return nil, fmt.Errorf("unmarshal history error: %s", err)
		}

		// Filter based on queryType
		if queryType == "exchange" && history.OriginOwnerId == originOwner {
			continue
		}

		histories = append(histories, history)
	}

	return histories, nil
}

// QueryIPFSHashTransaction retrieves the IPFS hash associated with a digital right from the private data collection.
// This function requires the owner's ID and the digital right ID as input and returns the IPFS hash.
// Returns:
// - The IPFS hash associated with the digital right.
// - An error in case of any issues during the retrieval process.
func (c *DRM) QueryIPFSHashTransaction(ctx contractapi.TransactionContextInterface, ownerId string, digitalrightId string) (string, error) {
	// Construct the key for the digital right in the private data collection
	privateDataKey := constructDigitalrightKey(digitalrightId)

	// Get the IPFS hash from the private data collection
	ipfsHashBytes, err := ctx.GetStub().GetPrivateData(collectionName, privateDataKey)
	if err != nil {
		return "", fmt.Errorf("get IPFS hash error: %s", err)
	}

	// Construct the key for the original owner's digital rights
	ownerDigitalRightsKey := constructUserKey(ownerId)

	// Get the original owner's digital rights from the ledger
	ownerDigitalRightsBytes, err := ctx.GetStub().GetState(ownerDigitalRightsKey)
	if err != nil {
		return "", fmt.Errorf("get owner's digital rights error: %s", err)
	}

	// Unmarshal the owner's digital rights
	ownerDigitalRights := User{}
	if err := json.Unmarshal(ownerDigitalRightsBytes, &ownerDigitalRights); err != nil {
		return "", fmt.Errorf("unmarshal owner's digital rights error: %s", err)
	}

	// Check if the digital right ID is in the original owner's digital rights
	isOwner := false
	for _, rightID := range ownerDigitalRights.Digitalrights {
		if rightID == digitalrightId {
			isOwner = true
			break
		}
	}

	if !isOwner {
		return "", fmt.Errorf("only the owner can query the IPFS hash")
	}

	return string(ipfsHashBytes), nil
}

// ListDigitalrightsTransaction lists all digital rights (IDs and names) on the network.
// This function retrieves digital rights from the ledger and returns a JSON representation
// of a list containing digital right IDs and names.
// Returns:
// - A list of structs, where each struct contains digital right ID and name.
// - An error in case of any issues during the retrieval process.

// @Transaction(false)
func (c *DRM) ListDigitalrightsTransaction(ctx contractapi.TransactionContextInterface) ([]struct {
	Id   string `json:"id"`
	Name string `json:"name"`
}, error) {
	// Create an iterator to iterate over all digital rights
	digitalrightsIterator, err := ctx.GetStub().GetStateByPartialCompositeKey("", []string{"digitalright"})
	if err != nil {
		return nil, fmt.Errorf("query digitalrights error: %s", err)
	}
	defer digitalrightsIterator.Close()

	// Create a slice to store digital right information
	digitalrightsList := make([]struct {
		Id   string `json:"id"`
		Name string `json:"name"`
	}, 0)

	// Iterate over the digital rights and extract IDs and names
	for digitalrightsIterator.HasNext() {
		digitalrightKeyValue, err := digitalrightsIterator.Next()
		if err != nil {
			return nil, fmt.Errorf("get digitalright key-value error: %s", err)
		}

		// Get the digital right data from the ledger
		digitalrightBytes, err := ctx.GetStub().GetState(digitalrightKeyValue.Key)
		if err != nil || len(digitalrightBytes) == 0 {
			return nil, fmt.Errorf("digitalright not found")
		}

		// Unmarshal the digital right data
		digitalright := new(Digitalright)
		if err := json.Unmarshal(digitalrightBytes, digitalright); err != nil {
			return nil, fmt.Errorf("unmarshal digitalright error: %s", err)
		}

		// Append the digital right ID and name to the list
		digitalrightsList = append(digitalrightsList, struct {
			Id   string `json:"id"`
			Name string `json:"name"`
		}{
			Id:   digitalright.Id,
			Name: digitalright.Name,
		})
	}

	return digitalrightsList, nil
}

// ListUsersTransaction lists all users (IDs and names) on the network.
// This function retrieves user data from the ledger and returns a JSON representation
// of a list containing user IDs and names.
// Returns:
// - A list of structs, where each struct contains user ID and name.
// - An error in case of any issues during the retrieval process.

// @Transaction(false)
func (c *DRM) ListUsersTransaction(ctx contractapi.TransactionContextInterface) ([]struct {
	Id   string `json:"id"`
	Name string `json:"name"`
}, error) {
	// Create an iterator to iterate over all users
	usersIterator, err := ctx.GetStub().GetStateByPartialCompositeKey("", []string{"user"})
	if err != nil {
		return nil, fmt.Errorf("query users error: %s", err)
	}
	defer usersIterator.Close()

	// Create a slice to store user information
	usersList := make([]struct {
		Id   string `json:"id"`
		Name string `json:"name"`
	}, 0)

	// Iterate over the users and extract IDs and names
	for usersIterator.HasNext() {
		userKeyValue, err := usersIterator.Next()
		if err != nil {
			return nil, fmt.Errorf("get user key-value error: %s", err)
		}

		// Get the user data from the ledger
		userBytes, err := ctx.GetStub().GetState(userKeyValue.Key)
		if err != nil || len(userBytes) == 0 {
			return nil, fmt.Errorf("user not found")
		}

		// Unmarshal the user data
		user := new(User)
		if err := json.Unmarshal(userBytes, user); err != nil {
			return nil, fmt.Errorf("unmarshal user error: %s", err)
		}

		// Append the user ID and name to the list
		usersList = append(usersList, struct {
			Id   string `json:"id"`
			Name string `json:"name"`
		}{
			Id:   user.Id,
			Name: user.Name,
		})
	}

	return usersList, nil
}

func main() {
	drmChaincode, err := contractapi.NewChaincode(&DRM{})
	if err != nil {
		log.Panicf("Error creating chaincode: %v", err)
	}

	if err := drmChaincode.Start(); err != nil {
		log.Panicf("Error starting chaincode: %v", err)
	}
}
