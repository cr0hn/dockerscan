dockerscan
==========

*dockerscan: A Docker analysis & hacking tools*

.. image::  https://github.com/cr0hn/dockerscan/raw/master/doc/source/_static/dockerscan-logo.png
    :height: 64px
    :width: 64px
    :alt: DockerScan logo

+----------------+--------------------------------------------------+
|Project site    | http://github.com/cr0hn/dockerscan               |
+----------------+--------------------------------------------------+
|Issues          | https://github.com/cr0hn/dockerscan/issues/      |
+----------------+--------------------------------------------------+
|Author          | Daniel Garcia (cr0hn) / Roberto Munoz (robskye)  |
+----------------+--------------------------------------------------+
|Documentation   | http://dockerscan.readthedocs.org                |
+----------------+--------------------------------------------------+
|Last Version    | 1.0.0-Alpha-01                                   |
+----------------+--------------------------------------------------+
|Python versions | 3.5 or above                                     |
+----------------+--------------------------------------------------+

What's dockerscan
=================

A Docker analysis tools

Very quick install
==================

.. code-block:: bash

    > python3.5 -m pip install -U pip
    > python3.5 -m pip install dockerscan

Show options:

.. code-block:: bash

    > dockerscan -h

Available actions
=================

Currently Docker Scan support these actions:

- Registry

    - Delete: Delete remote image / tag
    - Info: Show info from remote registry
    - Push: Push and image (like Docker client)
    - Upload: Upload random a file

- Image

    - Analyze: Looking for sensitive information in a Docker image.

        - Looking for passwords in environment vars.
        - Try to find any URL / IP in the environment vars.
        - Try to deduce the user using internally to run the software. This is not trivial. If the entry point is a .sh file. Read the file and try to find call to sudo-like: “sudo”, “gosu”, “sh -u”… And report the user found.

    - Extract: extract a docker image
    - info: Get a image meta information
    - modify:

        - entrypoint: change the entrypoint in a docker
        - **trojanize**: inject a reverser shell into a docker image
        - user: change running user in a docker image

What's the difference from Clair or Docker Cloud?
=================================================

The purpose of Dockerscan is a different. It's focussed in the attack fade. 

Although Dockescan has some functionalities to detect vulnerabilities into Docker images and Docker registries, the objetive is the attack. 

Documentation
=============

Documentation is still in process... sorry!

For the moment only have the Slides os presentation of RootedCON Spain. The conference where Docker Scan was presented:

https://www.slideshare.net/secret/fxVqD2iXqanOCX

Or you can watch it in video format (recommended):

https://youtu.be/OwX1e4y4JMk

Contributing
============

Any collaboration is welcome!

There're many tasks to do.You can check the `Issues <https://github.com/cr0hn/dockerscan/issues/>`_ and send us a Pull Request.

Also you can read the `TODO <https://github.com/cr0hn/dockerscan/blob/master/TODO.md>`_ file.

License
=======

This project is distributed under `BSD license <https://github.com/cr0hn/dockerscan/blob/master/LICENSE>`_

