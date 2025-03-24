#!/bin/bash

# Needs entr

find "wg-nf" -type f | entr sh -c "scp -r wg-nf server:"