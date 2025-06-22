# Fingerprint Module Library

This is a Python library for interacting with the fingerprint module backed by the AS608 Synochip processor. This includes the following fingerprint modules:

* AS608
* R307
* ZFM-20
* FPM10A
* GT-511C3

# Install

```
pip install git+https://github.com/omaraflak/fingerprint-module.git
```

# Module Overview

This library exposes the barebone commands provided by the module. This means you need a little background on how the module actually works to understand the library.

### Vocabulary

* "Feature": A feature is a set of intermediate data extracted from a raw fingerprint image. This data is not persisted.
* "Template": A template is a finalized, compressed version of the fingerprint features, ready for storage and matching. This is what is actually stored in the module after enrolling a fingerprint.

### Enrolling & Matching Overview

A high level description of how to register a fingerprint in the module is the following:

1- Scan the finger a first time to get an image
2- Extract the *features* of the fingerprint image
4- Repeat 1 & 2 a second time (for the same finger)
5- Combine both feature sets into a single *template*
6- Store the template in the persistent memory

When you want to match a given fingerprint against the stored fingerprints in the modules, you do the following:

1- Scan the finger to match
2- Extract the *features* of the fingerprint image
4- Compare the *features* extracted with a *template* from the library

### Non-Persistent Memory (RAM)

The module has **3** different temporary memory locations (memory that is not persisted when the module shuts down).

* **Image Buffer**
  * This location is dedicated to the store the image of the finger placed on the module during the capture. Typically, when using `capture_finger_image`, the image will be stored in this buffer. You can then read this image using `read_image_buffer`. The image is in grey scale and of dimension `256x288`. However, when read, the module will return only the 4 upper bits of each pixel. Which means 1 byte for 2 pixels. That is `256*288/2=36864` bytes are returned, which correspond to all pixels flattened by row. It is up to you to reconstruct the image.
* **Buffer 1**
  * This location is meant to hold a fingerprint "features" or "template" (depending on which step of the capture you're in). When you call `extract_features(buffer_id)`, the module will extract the features and write then to the buffer provided (`BUFFER_1` or `BUFFER_2`). When you call `generate_template`, the module will combine the content of `BUFFER_1` and `BUFFER_2` into a fingerprint template, and store it back into both `BUFFER_1` and `BUFFER_2`.
* **Buffer 2**
  * Same as Buffer 1.

### Persistent Memory (Flash)

The module has **2** different flash memory locations (memory that is persisted when the module shuts down).

* **Template Library**
  * This memory holds the templates of the fingerprints. It can only be accessed via indices, where an index represents a certain template. The specific number of templates that a module can hold can vary by model — which you can get using `read_system_parameters`.
* **Notepad**
  * This memory is 512 bytes long, and can be read/written by chunks of 32 bytes. It is split in 16 pages (16 * 32 = 512), and whenever you write a page, the whole 32 bytes of that page are overwritten.