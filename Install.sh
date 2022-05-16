
echo 'update and upgrade repository'
sudo apt-add-repository ppa:fish-shell/release-3
sudo apt-get update
sudo apt-get upgrade
sudo apt-get install fish
sudo apt-get install ruby
sudo apt-get install screen
sudo apt-get install python3
sudo apt-get install git
sudo apt-get install python3-pip
sudo apt install -y libpcap-dev
sudo apt-get install -y python-pip
sudo apt-get install snapd
sudo apt-get install python3-virtualenv
sudo apt-get install masscan
sudo apt install tor
sudo apt install python3-socks
sudo apt install chromium-browser
pip3 install requests bs4
pip3 install requests
pip install dnspython gevent
pip install aiodns
pip install shodan
pip3 install dnsgen

bash -c "$(curl -fsSL https://raw.githubusercontent.com/ohmybash/oh-my-bash/master/tools/install.sh)"


echo 'installing go'

wget https://go.dev/dl/go1.17.6.linux-amd64.tar.gz
sudo tar -xvf go1.17.6.linux-amd64.tar.gz
sudo mv go /usr/local
export GOROOT=/usr/local/go
export GOPATH=$HOME/go
export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
echo 'export GOROOT=/usr/local/go' >> ~/.bashrc
echo 'export GOPATH=$HOME/go'   >> ~/.bashrc
echo 'export PATH=$GOPATH/bin:$GOROOT/bin:$PATH' >> ~/.bashrc
source ~/.bashrc
rm -r go1.17.6.linux-amd64.tar.gz
sleep 1

echo 'download wordlists'

mkdir recon
mkdir wordlists
mkdir tools

go install github.com/tomnomnom/anew@latest

cd wordlists
        wget https://raw.githubusercontent.com/Cybversum/Wordlists/main/lfi.txt
        wget https://raw.githubusercontent.com/harsh-bothra/Bheem/master/arsenal/subdomains.txt
        wget https://raw.githubusercontent.com/harsh-bothra/Bheem/master/arsenal/resolvers.txt
        wget https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt
                cat best-dns-wordlist.txt | anew subdomains.txt
                rm best-dns-wordlist.txt
        wget https://wordlists-cdn.assetnote.io/data/automated/httparchive_apiroutes_2020_11_20.txt
                mv httparchive_apiroutes_2020_11_20.txt api.txt
        wget https://wordlists-cdn.assetnote.io/data/automated/httparchive_aspx_asp_cfm_svc_ashx_asmx_2020_11_18.txt
                mv httparchive_aspx_asp_cfm_svc_ashx_asmx_2020_11_18.txt aspx_asp_cfm_svc_ashx_asmx.txt
        wget https://wordlists-cdn.assetnote.io/data/automated/httparchive_directories_1m_2020_11_18.txt
                mv httparchive_directories_1m_2020_11_18.txt paths.txt
        wget https://wordlists-cdn.assetnote.io/data/manual/xml_filenames.txt
        wget https://wordlists-cdn.assetnote.io/data/automated/httparchive_xml_2020_11_18.txt
                cat httparchive_xml_2020_11_18.txt | anew xml_filenames.txt
                rm httparchive_xml_2020_11_18.txt
        wget https://wordlists-cdn.assetnote.io/data/automated/httparchive_html_htm_2020_11_18.txt
                mv httparchive_html_htm_2020_11_18.txt html_htm.txt
        wget https://wordlists-cdn.assetnote.io/data/automated/httparchive_jsp_jspa_do_action_2020_11_18.txt
                mv httparchive_jsp_jspa_do_action_2020_11_18.txt jsp_jspa_do_action.txt
        wget https://wordlists-cdn.assetnote.io/data/automated/httparchive_php_2020_11_18.txt
        wget https://wordlists-cdn.assetnote.io/data/manual/php.txt
                cat httparchive_php_2020_11_18.txt | anew php.txt
                rm httparchive_php_2020_11_18.txt
        git clone https://github.com/danielmiessler/SecLists.git
        git clone https://github.com/Karanxa/Bug-Bounty-Wordlists
        wget https://raw.githubusercontent.com/Cybversum/Wordlists/main/configs.txt

        mkdir webcache
        cd webcache
                wget https://raw.githubusercontent.com/Hackmanit/Web-Cache-Vulnerability-Scanner/master/wordlists/headers
                wget https://raw.githubusercontent.com/PortSwigger/param-miner/master/resources/headers
                wget https://raw.githubusercontent.com/Hackmanit/Web-Cache-Vulnerability-Scanner/master/wordlists/parameters
                wget https://raw.githubusercontent.com/PortSwigger/param-miner/master/resources/params
                cat params | anew parameters
                cat headers.1 | anew headers
                rm params
                rm headers.1
        cd ..
        mkdir payloads
        cd payloads
                wget https://raw.githubusercontent.com/Cybversum/Wordlists/main/lfi.txt
                echo "/v1/docs//..\\\..\\\..\\\..\\\..\\\..\\\..\\\..\\\..\\\..\\\..\\\..\\\..\\\..\\\..\\\..\\\/etc/passwd" | anew lfi.txt
                wget https://raw.githubusercontent.com/Cybversum/Wordlists/main/xss_payload.txt
                #xss, sqli, user/pass,
        cd ..
        mv ~/wordlists/SecLists/Discovery/Web-Content/raft-large-words.txt ~/wordlists
cd ..

echo 'download & install tools'

cd tools

        apt-get install nikto

        go install github.com/google/log4jscanner@latest

        https://github.com/laconicwolf/Masscan-to-CSV
        cd Masscan-to-CSV
                sudo chmod +x masscan_xml_parser.py
        cd ..

        wget https://gitlab.com/api/v4/projects/33695681/packages/generic/nrich/latest/nrich_latest_amd64.deb
        sudo dpkg -i nrich_latest_amd64.deb
        go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
        ##################
        #TOOLS SUBDOMAINS
        ##################
        sudo snap install amass
         go install github.com/takshal/freq@latest
        go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest

        go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

        GO111MODULE=on go get -v github.com/projectdiscovery/chaos-client/cmd/chaos

        go install -v github.com/tomnomnom/assetfinder@latest

        git clone https://github.com/gwen001/github-search

        wget https://github.com/findomain/findomain/releases/latest/download/findomain-linux
        chmod +x findomain-linux
        ./findomain-linux

        git clone https://github.com/devanshbatham/FavFreak
        cd FavFreak
        #       virtualenv -p python3 env
        #       source env/bin/activate
                python3 -m pip install mmh3
        cd ..

        git clone https://github.com/aboul3la/Sublist3r.git
        cd Sublist3r
                sudo pip install -r requirements.txt
        cd ..

    git clone https://github.com/edoardottt/cariddi.git; cd cariddi; go get; make linux
    cd ..

        GO111MODULE=on go get -v github.com/projectdiscovery/shuffledns/cmd/shuffledns
        git clone https://github.com/blechschmidt/massdns.git
        cd massdns
                make
                cd bin
                        mv massdns /usr/local/bin
                cd ..
        cd ..

        git clone https://github.com/the-c0d3r/admin-finder.git
        cd admin-finder
                pip3 install -r requirements.txt
        cd ..

        mkdir aquatone9
        cd aquatone9
                wget https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip
                unzip aquatone_linux_amd64_1.7.0.zip
                mv aquatone ~/go/bin/
        cd ..

        git clone https://github.com/mIcHyAmRaNe/okadminfinder3.git
        cd okadminfinder3
                chmod +x okadminfinder.py
                pip3 install -r requirements.txt
                python3 okadminfinder.py
        cd ..
        go install github.com/tomnomnom/meg@latest
        go install github.com/j3ssie/metabigor
        pip3 install s3scanner
        go install github.com/hakluke/hakrawler@latest
        go install github.com/jaeles-project/gospider@latest
        git clone https://github.com/nsonaniya2010/SubDomainizer.git
        cd SubDomainizer
                pip3 install -r requirements.txt
        cd ..
        git clone https://github.com/gwen001/github-search
        git clone https://github.com/infosec-au/altdns
        cd altdns
                pip3 install -r requirements.txt
        cd ..
        pip3 install py-altdns==1.0.2

        #Bypass
        git clone https://github.com/iamj0ker/bypass-403
        cd bypass-403
                chmod +x bypass-403.sh
                sudo apt install figlet
        cd ..

        git clone https://github.com/lobuhi/byp4xx.git
        cd byp4xx
                chmod u+x byp4xx.py
        cd ..

        git clone https://github.com/yunemse48/403bypasser
        cd 403bypasser
                pip install -r requirements.txt
        cd ..

        git clone https://github.com/Dheerajmadhukar/4-ZERO-3

        ##################
        #TOOLS URLS
        ##################
        go install github.com/mhmdiaa/chronos@latest
        go install github.com/tomnomnom/waybackurls@latest
        GO111MODULE=on go get -u -v github.com/bp0lr/gauplus
        go install github.com/lc/gau/v2/cmd/gau@latest
        go install github.com/tomnomnom/gf@latest
        git clone https://github.com/devanshbatham/ParamSpider
        cd ParamSpider
                pip3 install -r requirements.txt
        cd ..

        mkdir gf-patterns
        cd gf-patterns
                git clone https://github.com/tomnomnom/gf
                git clone https://github.com/1ndianl33t/Gf-Patterns
                git clone https://github.com/dwisiswant0/gf-secrets
                git clone https://github.com/robre/gf-patterns
        cd ..
        pip3 install uro

        ##################
        ## Email
        ##################
        git clone https://github.com/m4ll0k/Infoga.git
        cd Infoga
                python setup.py install
                python infoga.py
        cd ..

        git clone https://github.com/davidtavarez/pwndb.git
        cd pwndb
                pip install -r requirements.txt
        cd ..

        ##################
        #JS
        ##################
        GO111MODULE=on go get -u -v github.com/lc/subjs@latest
        go install https://github.com/gwen001/github-subdomains@latest

        git clone https://github.com/Threezh1/JSFinder

        git clone https://github.com/KathanP19/JSFScan.sh
        cd JSFScan.sh
                sudo chmod +x install.sh
                ./install.sh
        cd ..

        git clone https://github.com/m4ll0k/gmapsapiscanner

        go install github.com/003random/getJS@latest

        ##################
        #Dorks
    ##################
        git clone https://github.com/opsdisk/pagodo.git
        cd pagodo
                pip3 install -r requirements.txt
                python3 ghdb_scraper.py -s -j -i
        cd ..

        git clone https://github.com/obheda12/GitDorker
        cd GitDorker
                pip3 install -r requirements.txt
        cd ..

        git clone https://github.com/m3n0sd0n4ld/uDork
        cd uDork
                chmod +x uDork.sh
        cd ..

        git clone https://github.com/techgaun/github-dorks
        cd github-dorks
                pip install .
        cd ..

        git clone https://github.com/zricethezav/gitleaks.git
        cd gitleaks
                make build
        cd ..

        git clone https://github.com/IvanGlinkin/Fast-Google-Dorks-Scan

        ##################
        #Port Scans
        ##################
        sudo apt-get install -y nmap

        cargo install rustscan

        git clone https://github.com/p33kab00/dns-masscan.git

        git clone https://github.com/x90skysn3k/brutespray
        cd brutespray
                pip3 install -r requirements.txt
        cd ..

        go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

        sudo git clone https://github.com/offensive-security/exploitdb.git /opt/exploitdb
        sudo ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit

        ##################
        #Others
        ##################
        go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
        pip3 install dirsearch

        git clone https://github.com/hisxo/gitGraber
        cd gitGraber
                pip3 install -r requirements.txt
        cd ..

        git clone https://github.com/TheRook/subbrute.git

        git clone https://github.com/ffuf/ffuf
        cd ffuf
                go get
                go build
        cd ..

        pip3 install arjun
        go install github.com/tomnomnom/fff@latest
        go install github.com/tomnomnom/unfurl@latest
        go install github.com/tomnomnom/qsreplace@latest
        go install github.com/Emoe/kxss@latest
        go install github.com/KathanP19/Gxss@latest

        ##################
        #Scans
        ##################
        git clone https://github.com/urbanadventurer/WhatWeb.git
        cd WhatWeb/
                make install
        cd ..

        git clone https://github.com/21y4d/nmapAutomator
        sudo ln -s $(pwd)/nmapAutomator/nmapAutomator.sh /usr/local/bin/

        go install -v github.com/Hackmanit/Web-Cache-Vulnerability-Scanner@latest

        sudo snap install sqlmap

        git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev
        go install github.com/hahwul/dalfox/v2@latest
        go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
        nuclei -ut

        sudo pip install corscanner

        git clone https://github.com/s0md3v/Corsy
        cd Corsy
                pip3 install requests
        cd ..

        git clone https://github.com/mazen160/bfac
        go install -v github.com/lukasikic/subzy@latest

        ##ATENÇAO CD

        cd --
        mkdir .gf

        cd ~/.gf; wget https://raw.githubusercontent.com/devanshbatham/ParamSpider/master/gf_profiles/potential.json;
        cd ..

        mv ~/tools/gf-patterns/gf/examples/*.json ~/.gf/;
        mv ~/tools/gf-patterns/Gf-Patterns/*.json ~/.gf/;
        mv ~/tools/gf-patterns/gf-secrets/.gf/*.json ~/.gf/;
        mv ~/tools/gf-patterns/gf-patterns/xml.json ~/.gf/;

        #nmap scripts
        cd /usr/share/nmap/scripts
                git clone https://github.com/glennzw/shodan-hq-nse
                git clone https://github.com/vulnersCom/nmap-vulners
                git clone https://github.com/scipag/vulscan
        cd --

        bind TAB:menu-complete

        ########
        #Alias
        ########
        echo "
        alias gmapi='python3 ~/tools/gmapsapiscanner/maps_api_scanner_python3.py'
        alias linkfinder='python3 ~/tools/JSFScan.sh/tools/LinkFinder/linkfinder.py'
        alias secretfinder='python3 ~//tools/JSFScan.sh/tools/SecretFinder/SecretFinder.py'
        alias findomain='~/tools/findomain-linux'
        " >> ~/.bashrc;

        source ~/.bashrc

        echo "chaos api"
        echo "falta credentials https://github.com/m3n0sd0n4ld/uDork"
        echo "uDork -> c_user=100076472047024; xs=23%3A1qKIC8Lww8iD0A%3A2%3A1640303623%3A-1%3A-1;"
