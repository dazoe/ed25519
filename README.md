# ed25519
A native implementation of Ed25519(http://ed25519.cr.yp.to/) for node.js

## Installation
npm install ed25519

### Windows Prerequisites
1. Install Python version 2.7 from https://www.python.org/ . You can install just for your local user account or for all users. Version 2.7 is required for building the Ed25519 native code package. Set the path to python.exe in the PYTHON environment variable.
1. Install Visual Studio 2017 Build Tools from https://www.visualstudio.com/thank-you-downloading-visual-studio/?sku=BuildTools&rel=15 . Select the Visual C++ Build Tools suite from the Workloads tab.
1. (Windows) Install the latest Win64 version of the full (non-Lite) installer for OpenSSL from https://slproweb.com/products/Win32OpenSSL.html to `c:\OpenSSL-Win64` . Version 1.1.1a or higher is required.

## Usage
For usage details see the example.js file.

## License
Copyright (c) 2013, Dave Akers
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
