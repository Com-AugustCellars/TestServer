#!/bin/bash
set -ev

dotnet build --configuration $VERSION  $SLN
