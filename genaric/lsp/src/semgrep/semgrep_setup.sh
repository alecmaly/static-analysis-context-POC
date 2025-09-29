
git clone https://github.com/MobSF/mobsfscan.git ./sg-rules/mobsfscan &
git clone https://github.com/0xdea/semgrep-rules.git ./sg-rules/0xdea &
git clone https://github.com/trailofbits/semgrep-rules.git ./sg-rules/trailofbits &
git clone https://github.com/elttam/semgrep-rules.git ./sg-rules/elttam &
git clone https://gitlab.com/gitlab-org/security-products/sast-rules.git ./sg-rules/gitlab &
git clone https://github.com/kondukto-io/semgrep-rules.git ./sg-rules/kondukto &
git clone https://github.com/hashicorp-forge/semgrep-rules.git ./sg-rules/hashicorp-forge &
git clone https://github.com/dgryski/semgrep-go.git ./sg-rules/dgryski &
git clone https://github.com/mindedsecurity/semgrep-rules-android-security.git ./sg-rules/mindedsecurity &
git clone https://github.com/federicodotta/semgrep-rules.git ./sg-rules/federicodotta &

# git clone in background, wait for completion
wait
printf "All git clones completed\n"

# modify mobsfscan dir
mv ./sg-rules/mobsfscan/mobsfscan/rules/semgrep ./sg-rules/mobsf
rm -rf ./sg-rules/mobsfscan


cat /app/semgrep/todelete.txt | xargs rm


i=0
while true; do
    i=$((i+1))
    echo "[+] Running semgrep scan --valudate to find errors and remove them (loop $i)"
    semgrep scan --validate --config ./sg-rules 2>&1 | tee errors.txt
    cat errors.txt | grep sg-rules | rev | cut -d' ' -f1 | rev | cut -d':' -f1 | sort | uniq > to_delete.txt
    cat to_delete.txt >> alldeleted.txt

    cat to_delete.txt | xargs rm

    if [ ! -s to_delete.txt ]; then
        break
    fi
done