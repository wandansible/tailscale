Ansible role: tailscale
=======================

Install, configure and authenticate a tailscale client with a tailscale network.

Requirements
------------

To use this role, the python package `netaddr` must be installed on the host running ansible.

Role Variables
--------------

```
ENTRY POINT: main - Install and configure tailscale

        Install, configure and authenticate a tailscale client with a
        tailscale network.

OPTIONS (= is mandatory):

- tailscale_apt_key_fingerprint
        Fingerprint for tailscale apt repo GPG key
        default: 2596A99EAAB33821893C0A79458CA832957F5868
        type: str

- tailscale_apt_key_url
        URL for tailscale apt repo GPG key
        default: "{{ \"https://pkgs.tailscale.com/\" + tailscale_version + \"/\"\n   + ansible_distribution
          | lower + \"/\" + ansible_distribution_release + \".noarmor.gpg\" }}"
        type: str

- tailscale_apt_repo
        Entry for tailscale apt repo in sources.list file
        default: "{{ \"https://pkgs.tailscale.com/\" + tailscale_version + \"/\"\n   + ansible_distribution
          | lower + \" \" + ansible_distribution_release + \" main\" }}"
        type: str

- tailscale_args
        List of arguments to provide to tailscale login and set
        commands
        See tailscale documentation for more details
        https://tailscale.com/kb/1080/cli
        default: []
        type: list

- tailscale_auth_key
        Tailscale authentication key starting with "tskey-auth" or
        oauth client secret starting with "tskey-client" to use for
        unattended login to the tailscale network. Or empty string to
        authenticate manually through a web browser.
        default: ''
        type: str

- tailscale_config
        Tailscale configuration file options
        default: {}
        type: dict

        OPTIONS:

        - AcceptDNS
            Accept DNS configuration from the tailscale admin panel
            default: null
            type: bool

        - AcceptRoutes
            Accept routes advertised by other tailscale nodes
            default: true
            type: bool

        - AdvertiseRoutes
            List of routes to advertise to other nodes
            default: null
            elements: str
            type: list

        - AllowLANWhileUsingExitNode
            Allow direct access to the local network when routing
            traffic via an exit node
            default: null
            type: bool

        - AuthKey
            Tailscale authentication key
            default: null
            type: str

        - AutoUpdate
            Autoupdate preferences for tailscale
            default: null
            type: dict

            OPTIONS:

            - Apply
                If true, tailscale will apply available updates in the
                background. Check must always be set when Apply is
                set.
                default: null
                type: bool

            - Check
                If true, tailscale will periodically check for
                available updates and notify the user about them
                default: null
                type: bool

        - DisableSNAT
            Disable source NAT for traffic to local advertised routes
            default: null
            type: bool

        - Enabled
            If true, tailscaled will start
            default: true
            type: bool

        - ExitNode
            Tailscale exit node (IP or name) for Internet traffic
            default: null
            type: str

        - Hostname
            Hostname to use instead of the one provided by the OS
            default: null
            type: str

        - Locked
            If true, the configuration file is locked from being
            changed by "tailscale set"
            default: false
            type: bool

        - NetfilterMode
            Netfilter mode
            choices: ['on', 'off', nodivert]
            default: null
            type: str

        - OperatorUser
            Local user name who is allowed to operate tailscaled
            without being root or using sudo
            default: null
            type: str

        - PostureChecking
            If true, enable posture checking
            default: null
            type: bool

        - RunSSHServer
            If true, enable tailscale ssh
            default: null
            type: bool

        - RunWebClient
            If true, enable tailscale web client
            default: null
            type: bool

        - ServerURL
            Tailscale server URL
            default: https://controlplane.tailscale.com
            type: str

        - ShieldsUp
            If true, don't allow incoming connections
            default: null
            type: bool

        - Version
            Tailscale configuration file version
            default: alpha0
            type: str

- tailscale_config_dir
        Directory for tailscale configuration
        default: /etc/tailscale
        type: str

- tailscale_login_timeout
        Time to wait for tailscale to generate an authentication URL
        default: 10s
        type: str

- tailscale_packages
        List of packages to install
        default: [tailscale]
        elements: str
        type: list

- tailscale_serve
        Tailscale serve configuration
        default: null
        elements: dict
        type: list

        OPTIONS:

        = from
            The port that will be opened on the tailscale network to
            serve up a local service
            type: dict

            OPTIONS:

            - path
                HTTP/HTTPS path to serve from. Must not be set when
                protocol is tcp or tls-terminated-tcp.
                default: /
                type: str

            = port
                Network port
                type: int

            = proto
                Network protocol
                choices: [http, https, tcp, tls-terminated-tcp]
                type: str

        - funnel
            If true, allow Internet to access the served port using
            tailscale funnel. Must not be true if the from protocol is
            set to http.
            default: null
            type: bool

        = to
            The target to serve onto the tailscale network. This can
            be a local file or directory, static text, or a local
            network service.
            File server Provide a full, absolute path to the file or
            directory of files you wish to serve. If a directory is
            specified, this will render a simple directory listing
            with links to files and sub-directories.
            Static text server Specifying text:<value> configures a
            simple static plain-text server.
            Reverse proxy The location to the local service can be
            expressed as a port number (for example, 3000), a partial
            URL (for example, localhost:3000), or a full URL including
            a path ( for example, tcp://localhost:3000/foo,
            https+insecure://localhost:3000/foo).
            type: str

- tailscale_serve_delete_unmanaged
        If true, delete any tailscale serve instances that are
        currently running but not configured by this ansible role.
        default: true
        type: bool

- tailscale_tailscaled_env_vars
        List of environment variables to pass to tailscaled
        default: []
        elements: dict
        type: list

        OPTIONS:

        = name
            Name of environment variable
            type: str

        = value
            Value of environment variable
            type: str

- tailscale_tailscaled_flags
        List of extra flags to pass to tailscaled
        default: "{{ []\n   + [\"-config=\" + tailscale_config_dir + \"/tailscaled.hujson\"]\n
          \  if tailscale_config != {} else [] }}"
        elements: str
        type: list

- tailscale_tailscaled_port
        The port tailscaled will listen on for incoming VPN packets
        default: 41641
        type: int

- tailscale_valid_args
        List of valid arguments for tailscale login and set commands
        default: [accept-dns, accept-routes, advertise-connector, advertise-exit-node, advertise-routes,
          exit-node, exit-node-allow-lan-access, hostname, netfilter-mode, nickname, operator,
          shields-up, snat-subnet-routes, ssh, stateful-filtering]
        type: list

- tailscale_valid_login_args
        List of valid arguments for tailscale login command only
        default: [advertise-tags, login-server]
        type: list

- tailscale_valid_set_args
        List of valid arguments for tailscale set command only
        default: [accept-risk, auto-update, update-check, webclient]
        type: list

- tailscale_version
        Version of tailscale to install
        choices: [stable, unstable]
        default: stable
        type: str
```

Installation
------------

This role can either be installed manually with the ansible-galaxy CLI tool:

    ansible-galaxy install git+https://github.com/wandansible/tailscale,main,wandansible.tailscale

Or, by adding the following to `requirements.yml`:

    - name: wandansible.tailscale
      src: https://github.com/wandansible/tailscale

Roles listed in `requirements.yml` can be installed with the following ansible-galaxy command:

    ansible-galaxy install -r requirements.yml

Example Playbook
----------------

    - hosts: all
      roles:
         - role: wandansible.tailscale
           become: true
           vars:
             tailscale_config:
               AcceptDNS: true
               RunSSHServer: true
               AutoUpdate:
                 Check: true
                 Apply: true

             tailscale_args:
               - option: "advertise-tags"
                 value: "tag:web-server,tag:ssh-server"

             tailscale_tailscaled_env_vars:
               - name: "TS_DEBUG_FIREWALL_MODE"
                 value: "nftables"
               - name: "TS_PERMIT_CERT_UID"
                 value: "caddy"

             tailscale_serve:
               - from:
                   proto: https
                   port: 1234
                 to: http://localhost:80
