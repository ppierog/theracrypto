# Theracrypto



## Getting started

To make it easy for you to get started with GitLab, here's a list of recommended next steps.

Already a pro? Just edit this README.md and make it your own. Want to make it easy? [Use the template at the bottom](#editing-this-readme)!

## Add your files

- [ ] [Create](https://docs.gitlab.com/ee/user/project/repository/web_editor.html#create-a-file) or [upload](https://docs.gitlab.com/ee/user/project/repository/web_editor.html#upload-a-file) files
- [ ] [Add files using the command line](https://docs.gitlab.com/ee/gitlab-basics/add-file.html#add-a-file-using-the-command-line) or push an existing Git repository with the following command:

```
cd existing_repo
git remote add origin https://gitlab.com/snowleopards/theracrypto.git
git branch -M main
git push -uf origin main
```

## Integrate with your tools

- [ ] [Set up project integrations](https://gitlab.com/snowleopards/theracrypto/-/settings/integrations)

## Collaborate with your team

- [ ] [Invite team members and collaborators](https://docs.gitlab.com/ee/user/project/members/)
- [ ] [Create a new merge request](https://docs.gitlab.com/ee/user/project/merge_requests/creating_merge_requests.html)
- [ ] [Automatically close issues from merge requests](https://docs.gitlab.com/ee/user/project/issues/managing_issues.html#closing-issues-automatically)
- [ ] [Enable merge request approvals](https://docs.gitlab.com/ee/user/project/merge_requests/approvals/)
- [ ] [Set auto-merge](https://docs.gitlab.com/ee/user/project/merge_requests/merge_when_pipeline_succeeds.html)

## Test and Deploy

Use the built-in continuous integration in GitLab.

- [ ] [Get started with GitLab CI/CD](https://docs.gitlab.com/ee/ci/quick_start/index.html)
- [ ] [Analyze your code for known vulnerabilities with Static Application Security Testing (SAST)](https://docs.gitlab.com/ee/user/application_security/sast/)
- [ ] [Deploy to Kubernetes, Amazon EC2, or Amazon ECS using Auto Deploy](https://docs.gitlab.com/ee/topics/autodevops/requirements.html)
- [ ] [Use pull-based deployments for improved Kubernetes management](https://docs.gitlab.com/ee/user/clusters/agent/)
- [ ] [Set up protected environments](https://docs.gitlab.com/ee/ci/environments/protected_environments.html)

***

# Editing this README

When you're ready to make this README your own, just edit this file and use the handy template below (or feel free to structure it however you want - this is just a starting point!). Thanks to [makeareadme.com](https://www.makeareadme.com/) for this template.

## Suggestions for a good README

Every project is different, so consider which of these sections apply to yours. The sections used in the template are suggestions for most open source projects. Also keep in mind that while a README can be too long and detailed, too long is better than too short. If you think your README is too long, consider utilizing another form of documentation rather than cutting out information.

## TheraCrypto
Small WASM project to do RSA/ AES in WASM.


## Description
Theracrypto is a WASM trusty zone written in GO. It gives possibility to do RSA in WASM.
As there syscall/js api is not so stable, this pice of code could be not so stable also:)
There is one PrivateKey storage and 3 additionall PublicKey storages in the WASM.
User can generate via GeneratePrivateKey() as well, as can load PrivateKey via LoadPrivateKey().
For PublicKeys there is only possibility to load via LoadPublicKey() to the one of predefined banks in the WASM memory.

Basic API Description in js:
Each functions returns js object like below :
{
    "error" : string // string value present only in case of error
    "ret"   : T // return in case of no errors, where T is a return type from function below
}

GeneratePrivKey(int keyLength) -> bool
Generate Private key in trusty WASM zone, returns true if success. Supported key length
is 2048 or 4096.

FetchPrivKey() -> b64 string
Fetch Private Key from WASM - returns marshaled Private Key which is next converted to base64 string.

LoadPrivKey(base64 string) -> bool
Load base64 Private Key to trusty WASM - returns true if this key can be decoded from base64 and loaded to memory.

LoadPubKey(base64 string , keyNum int) -> bool
Load base64 Public Key to trusty WASM - return true if this key can be decoded from base64 and loaded to memory.
User can load only to banks 1, 2, 3, beacuse of bank 0 is reserved for Public Key which is derived from Private Key.
Assuming the PrivateKey is loaded in the memory via GeneratePrivateKey() or LoadPrivateKey(). User can fetch PrivateKey
via FetchPrivateKey() and Public part of Key by FetchPublicKey(0)

FetchPubKey(keyNum) -> b64 string
Fetch PubKey from wasm memory marshaled and converted to base64 string.
FetchPubKey(0) - Fetch complementary of PrivateKey
FetchPubKey(x) - Fetch Pub Key previously loaded by LoadPubKey(), where x is bank in WASM memory : 1, 2 ,3

Encrypt(data []uint8) -> cipher []uint8
Encrypt with Public Key which is complementary to PrivateKey
Encrypt(data) == EncryptPubKey(data, 0)

EncryptPublicKey(data []uint8) - cipher []uint8
Encrypt with Public Key from bank : 0 , 1, 2, 3

Decrypt(cipher []uint8) -> plain []uint8
Decrypt data with Private Key


## Badges
On some READMEs, you may see small images that convey metadata, such as whether or not all the tests are passing for the project. You can use Shields to add some to your README. Many services also have instructions for adding a badge.

## Visuals
Depending on what you are making, it can be a good idea to include screenshots or even a video (you'll frequently see GIFs rather than actual videos). Tools like ttygif can help, but check out Asciinema for a more sophisticated method.

## Installation
Within a particular ecosystem, there may be a common way of installing things, such as using Yarn, NuGet, or Homebrew. However, consider the possibility that whoever is reading your README is a novice and would like more guidance. Listing specific steps helps remove ambiguity and gets people to using your project as quickly as possible. If it only runs in a specific context like a particular programming language version or operating system or has dependencies that have to be installed manually, also add a Requirements subsection.

## Usage

    mySecret = "aslk1234567890"
    utf8Encode = new TextEncoder();
    encoded = utf8Encode.encode(mySecret);

    // Generate Private Key, size 2048 bits
    GenerateKey(2048)

    // Encrypt & Decrypt in WASM
    encrypted = Encrypt(encoded)
    decrypted = Decrypt(encrypted.ret)

    String.fromCharCode.apply(null, decrypted.ret)


## Support
Tell people where they can go to for help. It can be any combination of an issue tracker, a chat room, an email address, etc.

## Roadmap
If you have ideas for releases in the future, it is a good idea to list them in the README.

## Contributing
State if you are open to contributions and what your requirements are for accepting them.

For people who want to make changes to your project, it's helpful to have some documentation on how to get started. Perhaps there is a script that they should run or some environment variables that they need to set. Make these steps explicit. These instructions could also be useful to your future self.

You can also document commands to lint the code or run tests. These steps help to ensure high code quality and reduce the likelihood that the changes inadvertently break something. Having instructions for running tests is especially helpful if it requires external setup, such as starting a Selenium server for testing in a browser.

## Authors and acknowledgment
Show your appreciation to those who have contributed to the project.

## License
For open source projects, say how it is licensed.

## Project status
If you have run out of energy or time for your project, put a note at the top of the README saying that development has slowed down or stopped completely. Someone may choose to fork your project or volunteer to step in as a maintainer or owner, allowing your project to keep going. You can also make an explicit request for maintainers.
