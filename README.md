## Overview

W10-FaceMessenger @ Autopsy is an Autopsy data source ingest module that wraps around the stand-alone application [W10-FaceMessenger](https://github.com/ricardoapl/w10-facemessenger) to parse and create the following artifacts associated with the use of Facebook Messenger (Beta) on Windows 10:

- Contacts
- Messages
- Calls
- Cached images
- Deleted database records

## Installation

If you have never installed a third-party module in Autopsy, have a look at the official [Autopsy User Documentation](https://sleuthkit.org/autopsy/docs/user-docs/4.16.0/module_install_page.html).

To install W10-FaceMessenger @ Autopsy you must:

1. Create a folder named `w10-facemessenger` within `python_modules`
2. Place `ingest_module.py` into this new folder
3. Place the W10-FaceMessenger executable into this same folder

## Requirements

For the time being, you must run Microsoft Windows.

You also need a binary distribution of W10-FaceMessenger to run this module (see [here](https://github.com/ricardoapl/w10-facemessenger)).

## Usage

W10-FaceMessenger @ Autopsy expects a data source containing at least one Windows user profile directory such as `C:\Users\ricardoapl`.

If you would like to know more about running ingest modules in Autopsy, checkout the official [Autopsy User Documentation](https://sleuthkit.org/autopsy/docs/user-docs/4.16.0/ingest_page.html).

## Support

Please use the [issue tracker](https://github.com/ricardoapl/w10-facemessenger-autopsy/issues) to ask for help, request a new feature or report any bugs.

## Roadmap

- [ ] Distinguish between successful and lost calls
- [ ] Allow persistence of multimedia content through module options
- [ ] Handle multiple (consecutive) runs of the module in the same case

## Contributing

Have a look at the [contributing guidelines](https://github.com/ricardoapl/w10-facemessenger-autopsy/blob/master/CONTRIBUTING.md) before submitting any pull request.

## Authors

This software was originally developed by Osvaldo Rainha ([**@orainha**](https://github.com/orainha)) and Ricardo Lopes ([**@ricardoapl**](https://github.com/ricardoapl)) under the guidance of Miguel Frade ([**@mfrade**](https://github.com/mfrade)) and Patrício Domingues ([**@PatricioDomingues**](https://github.com/PatricioDomingues/)).

## License

W10-FaceMessenger @ Autopsy is available under the terms of the MIT License.