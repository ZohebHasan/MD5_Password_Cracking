#!/bin/bash


SOURCE_FILE="HybridPasswordCracker.java"
CLASS_NAME="HybridPasswordCracker"


if ! [ -x "$(command -v java)" ]; then
  echo 'Error: Java is not installed.' >&2
  echo 'Installing Java...'
  
  sudo apt-get update
  sudo apt-get install default-jdk -y

  if ! [ -x "$(command -v java)" ]; then
    echo 'Error: Java installation failed.' >&2
    exit 1
  fi
fi


echo "Compiling $SOURCE_FILE..."
javac $SOURCE_FILE


if [ $? -eq 0 ]; then
  echo "Compilation successful!"
else
  echo "Compilation failed."
  exit 1
fi


if [ -z "$1" ]; then
  echo "No input file provided. Please provide the input file as an argument."
  exit 1
fi

echo "Running the program with input file: $1..."
java $CLASS_NAME "$1"
