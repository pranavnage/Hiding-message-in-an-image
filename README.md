### Simple Steganography Tool

This is a straightforward tool for hiding encrypted messages inside images. It's designed for simplicity and reliability.

### How It Works

The script uses **LSB (Least Significant Bit) steganography** to embed a compressed and encrypted message into an image's pixel data. For this technique to work, the output image must be a **PNG** file. This is because PNG is a lossless format that preserves all the hidden data without any compression-related corruption.

### Usage

#### To Hide

```bash
python steganography_tool.py hide -i my_image.jpg -m "Your secret message." -p your_password -o output.png
```

  * `-i`, `--image`: Path to the image file to hide the message in.
  * `-m`, `--message`: The message you want to hide.
  * `-p`, `--password`: The password for encryption and decryption.
  * `-o`, `--output`: Optional. The path and filename for the output image. If not provided, the tool will create a file named `my_image_hidden.png`.

#### To Reveal

```bash
python steganography_tool.py reveal -i my_image_hidden.png -p your_password
```

  * `-i`, `--image`: Path to the image file containing the hidden message.
  * `-p`, `--password`: The password used for encryption.
