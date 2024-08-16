#!/bin/bash
echo "Executando script de pre-push de jhersonharyson..."

commitHash=$(git rev-parse HEAD)
echo "Commit Hash: $commitHash"
echo "Project Name: $project_name"
./upload.sh $project_name
