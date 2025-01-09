#!/usr/bin/env python3

"""
This python script gets disk images used in the unit tests.
Inputs:  test_images.yaml
Outputs:
   test images put in the directory specified in the test_images file
   test_images.txt, which is a tab-delimited file containing the input test image and the DFXML output

"""

import os
import os.path
import logging
import requests
import yaml
import zipfile
import re
import functools
import urllib
import shutil
from os.path import join,abspath,dirname,basename,splitext

MYDIR       = abspath(dirname( __file__ ))
TEST_IMAGES_YAML = join(MYDIR, "test_images.yaml")
TEST_IMAGES_TXT   = join(MYDIR, "test_images.txt")


@functools.lru_cache(maxsize=1)
def config():
    """Returns the YAML config, parsed"""
    with open(TEST_IMAGES_YAML,"r") as f:
        return yaml.safe_load(f)


@functools.lru_cache(maxsize=1)
def dest_dir():
    """Replace $HOME with the home directory"""
    return os.path.expandvars(config()['dest_dir'])


DEST_DIR = dest_dir()


def is_disk_image(name):
    m = DISK_IMAGE_EXTENSIONS.search( name )
    if m:
        return True
    return False


def getfile(url, dest):
    """Gets a file from url and puts it in dest. If url is not a URL, it copies the file"""
    if os.path.exists(dest):
        logging.info("   already exists: %s",dest)
        return

    os.makedirs( os.path.dirname(dest), exist_ok=True)
    o = urllib.parse.urlparse(url)
    if not o.scheme:
        logging.info("Copying %s -> %s", o.path, dest)
        shutil.copyfile(o.path, dest)
    else:
        logging.info("Downloading %s -> %s",url, dest)
        r = requests.get(url)
        with open( dest, "wb") as f:
            f.write(r.content)


def get_test_image(source):
    """Gets each test image and returns a pair of (imagefile, xmlfile)"""
    for (name,vals) in source.items():
        logging.info("Getting %s",name)
        if 'image' in vals:
            image_url = vals['image']
            image_fname = join( DEST_DIR, basename(image_url))
            getfile(image_url, image_fname)
        elif 'zipfile' in vals:
            zipfile_url = vals['zipfile']
            try:
                unzip_fname = vals['unzip_image']
            except KeyError as e:
                raise RuntimeError(f'no unzip_image specified in {vals}') from e
            zipfile_fname = join( DEST_DIR, basename(vals['zipfile']))
            image_fname   = join( DEST_DIR, basename(unzip_fname))

            getfile(zipfile_url, zipfile_fname)
            logging.info("Copied %s -> %s",zipfile_url,unzip_fname)

            def unzip_file():
                with zipfile.ZipFile(zipfile_fname) as zf:
                    with zf.open(unzip_fname, "r") as myfile:
                        with open(image_fname, "wb") as out:
                            out.write(myfile.read())
                            logging.info("Unzipped %s->%s",image_fname, unzip_fname)
                            return
                raise RuntimeError(f"did not file file {unzip_fname} in {zipfile_fname}")
            unzip_file()

        else:
            raise RuntimeError(f"no 'image' or 'zipfile' in {source}")

        # Now get the DFXML
        try:
            xml_source  = vals['xml']
            xml_fname   = join( DEST_DIR, basename(xml_source))
            getfile(xml_source, xml_fname)
        except KeyError:
            xml_fname = ''
        return image_fname, xml_fname


def get_test_images():
    " Gets all of the test images. Returns"
    with open(TEST_IMAGES_TXT, 'w') as out:
        for source in config()['sources']:
            image, xml = get_test_image(source)
            out.write(f"{image}\t{xml}\n")


if __name__=="__main__":
    logging.basicConfig()
    logging.getLogger().setLevel(logging.DEBUG)
    get_test_images()
