<p align="center">
  <img src="https://user-images.githubusercontent.com/48807108/85414813-7efba700-b564-11ea-85a6-2098fe48de87.png" width="64"/>
</p>

## About

W10-FaceMessenger @ Autopsy is an Autopsy data source-level ingest module that wraps around [W10-FaceMessenger](https://github.com/ricardoapl/w10-facemessenger) to extract the following content:
- Contacts
- Messages
- Cached images
- Deleted database records

## Supported platforms

W10-FaceMessenger @ Autopsy is designed to work with Windows.

Support for other platforms is not planned for the near future.

## Requirements

You need a binary distribution of W10-FaceMessenger to run this module (see [here](https://github.com/ricardoapl/w10-facemessenger)).

## Installation

Quoting [this](https://www.autopsy.com/python-autopsy-module-tutorial-1-the-file-ingest-module/) Autopsy blog post:

> To find out where you should put your Python module, launch Autopsy and choose the Tools -> Python Plugins menu item.
> That will open a folder in your AppData folder, such as “C:\Users\JDoe\AppData\Roaming\Autopsy\python_modules”.

To install W10-FaceMessenger @ Autopsy you must:
1. Create a folder named `w10-facemessenger` within `python_modules`
2. Place `ingest_module.py` into this new folder
3. Place the W10-FaceMessenger executable into this same folder

The final result should resemble:

```
python_modules/
└── w10-facemessenger
    ├── ingest_module.py
    └── w10-facemessenger.exe
```

## Usage

W10-FaceMessenger @ Autopsy expects a data source containing at least one Windows user profile directory such as `C:\Users\ricardoapl`.

## Authors

This software was originally developed by Osvaldo Rainha ([**@orainha**](https://github.com/orainha)) and Ricardo Lopes ([**@ricardoapl**](https://github.com/ricardoapl)) under the guidance of Miguel Frade ([**@mfrade**](https://github.com/mfrade)) and Patrício Domingues ([**@PatricioDomingues**](https://github.com/PatricioDomingues/)).

## License

W10-FaceMessenger is licensed under the MIT License.