# Use a lightweight Python image based on Debian
FROM python:3.12-slim

# Set the working directory inside the container
WORKDIR /app

# Update package lists and install necessary packages
RUN apt-get update && apt-get install -y --no-install-recommends git npm curl ccls python3-pylsp default-jre wget jq unzip zip vim gpg lsb-release clangd

# # install jdk 21, ghidra dependency
# RUN wget -O - https://packages.adoptium.net/artifactory/api/gpg/key/public | gpg --dearmor -o /usr/share/keyrings/adoptium-archive-keyring.gpg && \
#     echo "deb [signed-by=/usr/share/keyrings/adoptium-archive-keyring.gpg] https://packages.adoptium.net/artifactory/deb $(awk -F= '/^VERSION_CODENAME/{print$2}' /etc/os-release) main" | tee /etc/apt/sources.list.d/adoptium.list && \
#     apt-get update && \
#     apt-get install -y temurin-21-jdk

# install dotnet SDK
# docks https://learn.microsoft.com/en-us/dotnet/core/install/linux-debian
RUN wget https://packages.microsoft.com/config/debian/12/packages-microsoft-prod.deb -O packages-microsoft-prod.deb && \
    dpkg -i packages-microsoft-prod.deb && \
    rm packages-microsoft-prod.deb
    RUN apt-get update && apt-get install -y --no-install-recommends dotnet-sdk-9.0


# install powershell: https://learn.microsoft.com/en-us/powershell/scripting/install/install-debian?view=powershell-7.4
# RUN wget https://github.com/PowerShell/PowerShell/releases/download/v7.5.2/powershell_7.5.2-1.deb_amd64.deb
# RUN dpkg -i powershell_7.5.2-1.deb_amd64.deb
# RUN apt-get install -f
# RUN rm powershell_7.5.2-1.deb_amd64.deb

# remove the .deb steps and use this instead
RUN curl -L -o /tmp/pwsh.tar.gz \
        https://github.com/PowerShell/PowerShell/releases/download/v7.5.2/powershell-7.5.2-linux-x64.tar.gz \
    && mkdir -p /opt/microsoft/powershell/7 \
    && tar -xzf /tmp/pwsh.tar.gz -C /opt/microsoft/powershell/7 \
    && ln -s /opt/microsoft/powershell/7/pwsh /usr/bin/pwsh \
    && rm -rf /var/lib/apt/lists/* /tmp/pwsh.tar.gz \
    && chmod +x /usr/bin/pwsh
    



# install ruby language server dependencies
# docs: https://github.com/gosu/gosu/wiki/Getting-Started-on-Linux
RUN apt-get update && apt-get install -y --no-install-recommends build-essential libsdl2-dev libgl1-mesa-dev libgmp-dev libfontconfig1-dev ruby-dev


# Install npm packages
RUN npm i -g intelephense typescript typescript-language-server @nomicfoundation/solidity-language-server bash-language-server pyright


# https://github.com/fwcd/kotlin-language-server/tree/main
# Install Kotlin Language server
# RUN apt-get install -y openjdk-17-jdk

RUN mkdir -p /etc/apt/keyrings && \
    curl -fsSL https://packages.adoptium.net/artifactory/api/gpg/key/public | gpg --dearmor -o /etc/apt/keyrings/adoptium.gpg && \
    echo "deb [signed-by=/etc/apt/keyrings/adoptium.gpg] https://packages.adoptium.net/artifactory/deb $(. /etc/os-release && echo "$VERSION_CODENAME") main" > /etc/apt/sources.list.d/adoptium.list && \
    apt-get update && \
    apt-get install -y temurin-21-jdk

# RUN apt-get install -y default-jdk
RUN git clone https://github.com/fwcd/kotlin-language-server.git
# update /app/kotlin-language-server/gradle.properties
# update config to not use old java version (hardcoded, this is no bueno but works for now)
# RUN printf "version=1.9.10\njavaVersion=17\n" > /app/kotlin-language-server/gradle.properties
RUN printf "version=1.9.10\njavaVersion=21\n" > /app/kotlin-language-server/gradle.properties
RUN cd kotlin-language-server && ./gradlew :server:installDist
ENV PATH="/app/kotlin-language-server/server/build/install/server/bin:${PATH}"




# Create a non-root user and set permissions
# RUN useradd -ms /bin/bash myuser
# RUN chown -R myuser:myuser /app
# USER myuser


# Install Go 
RUN export GO_VERSION=$(curl -s https://go.dev/VERSION?m=text | head -n 1) && \
    wget https://go.dev/dl/${GO_VERSION}.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf ${GO_VERSION}.linux-amd64.tar.gz && \
    rm ${GO_VERSION}.linux-amd64.tar.gz

ENV PATH="/usr/local/go/bin:${PATH}"


# Install Go language server
RUN go install golang.org/x/tools/gopls@latest
ENV PATH="/root/go/bin:${PATH}"

# install SDK man package manage
# RUN curl -s "https://get.sdkman.io" | bash
# RUN export SDKMAN_DIR="$HOME/.sdkman"
# RUN echo '[[ -s "$HOME/.sdkman/bin/sdkman-init.sh" ]] && source "$HOME/.sdkman/bin/sdkman-init.sh"' >> ~/.bashrc

# # # install gradle
# RUN bash -c 'source "$HOME/.sdkman/bin/sdkman-init.sh" && sdk install gradle'

# Install Ruby language server
# RUN gem install --user-install solargraph ruby-lsp bundle
RUN gem install solargraph ruby-lsp bundle


# lua language server
RUN TAG=`curl -s "https://api.github.com/repos/LuaLS/lua-language-server/releases/latest" | jq -r '.tag_name'` && \
    wget https://github.com/LuaLS/lua-language-server/releases/download/${TAG}/lua-language-server-${TAG}-linux-x64.tar.gz && \
    mkdir -p lua-ls && \
    tar -xvzf lua-language-server-${TAG}-linux-x64.tar.gz -C lua-ls && \
    chmod +x ./lua-ls/bin/lua-language-server && \
    rm lua-language-server-${TAG}-linux-x64.tar.gz
ENV PATH="/app/lua-ls/bin:${PATH}"


# download C# language server
# https://github.com/OmniSharp/omnisharp-roslyn/releases/tag/v1.39.12
# RUN wget https://github.com/OmniSharp/omnisharp-roslyn/releases/latest/download/omnisharp-linux-x64-net6.0.tar.gz && \
#     mkdir -p omnisharp && \
#     tar -xvzf omnisharp-linux-x64-net6.0.tar.gz -C omnisharp && \
#     chmod +x omnisharp/OmniSharp && \
#     rm omnisharp-linux-x64-net6.0.tar.gz
# ENV PATH="/app/omnisharp:${PATH}"


# Install Rust and Rust Analyzer
ENV PATH="/root/.cargo/bin:${PATH}"
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y 
RUN rustup component add rust-analyzer

# Add Cargo and Go binaries to PATH

# install assembly language server
RUN cargo install asm-lsp

# install java language server
RUN wget 'https://www.eclipse.org/downloads/download.php?file=/jdtls/snapshots/jdt-language-server-latest.tar.gz' -O jdt-language-server-latest.tar.gz
RUN mkdir -p java-ls
RUN tar -xvzf jdt-language-server-latest.tar.gz -C java-ls
RUN rm jdt-language-server-latest.tar.gz


# install powershell language server
RUN wget https://github.com/PowerShell/PowerShellEditorServices/releases/latest/download/PowerShellEditorServices.zip
RUN unzip PowerShellEditorServices.zip -d powershell-ls
RUN rm PowerShellEditorServices.zip




# install jadx
RUN TAG=`curl -s "https://api.github.com/repos/skylot/jadx/releases/latest" | jq -r '.tag_name'` && \
    TAG_NO_V=`echo $TAG | sed 's/v//'` && \
    wget "https://github.com/skylot/jadx/releases/download/${TAG}/jadx-${TAG_NO_V}.zip" && \
    unzip jadx-${TAG_NO_V}.zip -d jadx
ENV PATH="/app/jadx/bin:${PATH}"




# # install ghidra 11.2 (direct link, should update to dynamic link)
# # @note may need older version of Ghidra for compatibility with ghidrecomp
# RUN wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.1.2_build/ghidra_11.1.2_PUBLIC_20240709.zip && \
#     unzip ghidra_11.1.2_PUBLIC_20240709.zip -d ghidra
# ENV PATH="/app/ghidra/ghidra_11.1.2_PUBLIC:${PATH}"

# # isntall ghidrecomp
# RUN pip install ghidrecomp
# ENV GHIDRA_INSTALL_DIR="/app/ghidra/ghidra_11.1.2_PUBLIC"


# # Copy the requirements.txt file (if you have one) to install pip packages
COPY requirements.txt .

# # Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install semgrep eth-wake 

# other useful tools
RUN npm install -g @mixer/parallel-prettier prettier


# install python language server
# RUN pip install pyright

ENV PATH="/root/.local/bin:${PATH}"

# copy segmrep files
COPY ./src/semgrep ./semgrep
RUN chmod +x /app/semgrep/semgrep_setup.sh
RUN /app/semgrep/semgrep_setup.sh

# copy csharp-ls config files
COPY ./src/csharp-ls ./csharp-ls

# install c# language server
# example from: https://github.com/SofusA/roslyn-language-server
RUN mkdir -p /app/csharp-ls/roslyn \
    && cd /app/csharp-ls/roslyn \
    && latest_version=$(dotnet package search Microsoft.CodeAnalysis.LanguageServer.neutral \
        --source https://pkgs.dev.azure.com/azure-public/vside/_packaging/vs-impl/nuget/v3/index.json \
        --prerelease --format json 2>/dev/null \
        | sed -n '/^{/,$p' \
        | jq -r '.searchResult[0].packages[0].latestVersion') \
    && (dotnet add package Microsoft.CodeAnalysis.LanguageServer.neutral -v $latest_version || true) \
    && printf "#!/bin/sh\n" > /usr/local/bin/csharp-ls \
    && printf "dotnet /app/csharp-ls/roslyn/out/microsoft.codeanalysis.languageserver.neutral/%s/content/LanguageServer/neutral/Microsoft.CodeAnalysis.LanguageServer.dll --logLevel=Information --extensionLogDirectory /app/csharp-ls/roslyn/log --stdio\n" "$latest_version" >> /usr/local/bin/csharp-ls \
    && chmod +x /usr/local/bin/csharp-ls


# needs to be installed here to work?... 
RUN pip install tree-sitter tree-sitter-typescript tree-sitter-c-sharp

RUN git clone https://github.com/RubixDev/tree-sitter-asm.git /app/tree-sitter-asm \
    && cd /app/tree-sitter-asm \
    && gcc -fPIC -c src/parser.c -o parser.o \
    && gcc -shared parser.o -o libtree-sitter-asm.so

RUN pip install /app/tree-sitter-asm

# # Copy additional scripts and entrypoint
COPY ./src .

# python path to custom module
ENV PYTHONPATH=/app/modules/

# # Set the working directory for outputs
WORKDIR /app/output

EXPOSE 5678

# # Set the default command to run the entrypoint script
ENTRYPOINT ["sh", "/app/entrypoint.sh"]
