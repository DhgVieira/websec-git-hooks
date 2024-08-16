#!/bin/bash
echo "Executando script de pre-push de jhersonharyson..."
commitHash=$(git rev-parse HEAD)
./upload.sh mgrowth-sameday-manager $commitHash
