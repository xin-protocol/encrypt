package main

import (
	"encoding/hex"
	"fmt"

	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/txnbuild"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// BuildApproveTransaction creates an unsigned transaction envelope XDR to simulate the approve contract call.
func BuildApproveTransaction(contractID string, objectIDHex string, callerAddress string) (string, error) {
	// 1. Decode Contract ID
	contractBytes, err := strkey.Decode(strkey.VersionByteContract, contractID)
	if err != nil {
		return "", fmt.Errorf("invalid contract ID: %w", err)
	}
	var contractIdHash xdr.Hash
	copy(contractIdHash[:], contractBytes)
	cId := xdr.ContractId(contractIdHash)

	var contractAddressXDR xdr.ScAddress
	contractAddressXDR.Type = xdr.ScAddressTypeScAddressTypeContract
	contractAddressXDR.ContractId = &cId

	// 2. Decode Object ID from hex to bytes
	objectIdBytes, err := hex.DecodeString(objectIDHex)
	if err != nil {
		return "", fmt.Errorf("invalid object ID hex: %w", err)
	}

	var objectIdVal xdr.ScVal
	objectIdVal.Type = xdr.ScValTypeScvBytes
	scBytes := xdr.ScBytes(objectIdBytes)
	objectIdVal.Bytes = &scBytes

	// 3. Decode Caller Address into ScAddress
	callerPubKeyBytes, err := strkey.Decode(strkey.VersionByteAccountID, callerAddress)
	if err != nil {
		return "", fmt.Errorf("invalid caller address: %w", err)
	}
	var callerAccountId xdr.AccountId
	callerAccountId.Type = xdr.PublicKeyTypePublicKeyTypeEd25519
	var edHash xdr.Uint256
	copy(edHash[:], callerPubKeyBytes)
	callerAccountId.Ed25519 = &edHash

	var callerScAddr xdr.ScAddress
	callerScAddr.Type = xdr.ScAddressTypeScAddressTypeAccount
	callerScAddr.AccountId = &callerAccountId

	var callerAddressVal xdr.ScVal
	callerAddressVal.Type = xdr.ScValTypeScvAddress
	callerAddressVal.Address = &callerScAddr

	// 4. Build Simple Account for Source
	sourceAccount := txnbuild.SimpleAccount{
		AccountID: callerAddress,
		Sequence:  0,
	}

	// 5. Build Soroban Operation
	invokeOp := &txnbuild.InvokeHostFunction{
		HostFunction: xdr.HostFunction{
			Type: xdr.HostFunctionTypeHostFunctionTypeInvokeContract,
			InvokeContract: &xdr.InvokeContractArgs{
				ContractAddress: contractAddressXDR,
				FunctionName:    xdr.ScSymbol("approve"),
				Args:            []xdr.ScVal{objectIdVal, callerAddressVal},
			},
		},
	}

	// 6. Build the Transaction
	tx, err := txnbuild.NewTransaction(
		txnbuild.TransactionParams{
			SourceAccount:        &sourceAccount,
			IncrementSequenceNum: false,
			Operations:           []txnbuild.Operation{invokeOp},
			BaseFee:              txnbuild.MinBaseFee,
			Preconditions: txnbuild.Preconditions{
				TimeBounds: txnbuild.NewInfiniteTimeout(),
			},
		},
	)
	if err != nil {
		return "", fmt.Errorf("failed to build Soroban transaction: %w", err)
	}

	// 7. Serialize to Base64 XDR
	xdrBase64, err := tx.Base64()
	if err != nil {
		return "", fmt.Errorf("failed to serialize transaction to XDR: %w", err)
	}

	return xdrBase64, nil
}
