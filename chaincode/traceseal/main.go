package main

import (
	"fmt"
	"os"

	"github.com/hyperledger/fabric-contract-api-go/v2/contractapi"
)

func main() {
	chaincode, err := contractapi.NewChaincode(new(TraceSealContract))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating traceseal chaincode: %v\n", err)
		os.Exit(1)
	}
	if err := chaincode.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "error starting traceseal chaincode: %v\n", err)
		os.Exit(1)
	}
}
