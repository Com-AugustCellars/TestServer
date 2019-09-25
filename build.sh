#!/bin/bash
set -ev

dotnet build --configuration $VERSION --framework=netcoreapp2.0 $SLN
