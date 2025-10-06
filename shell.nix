#{ pkgs ? import <nixpkgs> {} }:
{ pkgs ? import (fetchTarball "https://github.com/NixOS/nixpkgs/archive/nixos-unstable.tar.gz") {} }:
  pkgs.mkShell {
    nativeBuildInputs = with pkgs.buildPackages; 
	[ 
		python313
		python313Packages.aiohttp
		python313Packages.pydantic
		python313Packages.typing-extensions
		python313Packages.cryptography
		python313Packages.pytest
		python313Packages.pytest-asyncio
		python313Packages.pytest-cov
		python313Packages.click
		python313Packages.python-dateutil
		python313Packages.requests
		python313Packages.psutil	
		python313Packages.pyperclip
		python313Packages.pwntools
		python313Packages.uvicorn
		python313Packages.mcp
		uv
		open-policy-agent
	];
}
