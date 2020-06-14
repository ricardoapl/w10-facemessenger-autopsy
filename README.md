## About

W10-FaceMessenger @ Autopsy is an Autopsy data source-ingest module that wraps around [W10-FaceMessenger](https://github.com/ricardoapl/w10-facemessenger) to extract the following content:
- Contacts
- Messages
- Cached images
- Deleted database records

## Requirements

To run this module you need a binary distribution of W10-FaceMessenger (see [here](https://github.com/ricardoapl/w10-facemessenger)).

## Installation

Quoting [this](https://www.autopsy.com/python-autopsy-module-tutorial-1-the-file-ingest-module/) Autopsy blog post:

```
Every Python module in Autopsy gets its own folder. This reduces naming collisions between modules. To find out where you should put your Python module, launch Autopsy and choose the Tools -> Python Plugins menu item. That will open a folder in your AppData folder, such as “C:\Users\JDoe\AppData\Roaming\Autopsy\python_modules”.
```

To install W10-FaceMessenger @ Autopsy you must:
1. Create a folder named `w10-facemessenger` inside `python_modules`
2. Place `ingest_module.py` into this new folder
3. Place the W10-FaceMessenger executable into this same folder

The final result should resemble:

```
python_modules/
└── w10-facemessenger
    ├── ingest_module.py
    └── w10-facemessenger.exe
```

## Authors

This software was developed by Osvaldo Rainha ([**@orainha**](https://github.com/orainha)) and Ricardo Lopes ([**@ricardoapl**](https://github.com/ricardoapl)) under the guidance of Miguel Frade and Patrício Domingues.

## License

This software is distributed under the MIT License.