#!/bin/bash
echo "Executando script de pre-push de jhersonharyson..."

commitHash=$(git rev-parse HEAD)
echo "Commit Hash: $commitHash"
./upload.sh $project_name
