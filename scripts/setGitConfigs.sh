#!/bin/bash

read -p "What is the email you want to use for this git repo?: " EMAIL
git config --global user.email $EMAIL

read -p "What is your name?: " NAME
git config --global user.name $NAME

git config pull.rebase false

echo "done"
