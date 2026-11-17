# Terms of Use

Last updated: 17 November 2026

## VXControl Cloud SDK and PentAGI Cloud

These terms apply to the use of PentAGI Cloud services through the VXControl Cloud SDK (the "SDK"). The licensor is VXControl L.L.C-FZ, a company registered in the Meydan Free Zone, Dubai, United Arab Emirates (trade licence 2538161.01), with its address at Meydan Grandstand, 6th floor, Meydan Road, Nad Al Sheba, Dubai ("VXControl").

---

## 1. The SDK and its licence

The source code of the SDK is licensed under the MIT License (see [LICENSE](LICENSE)). These terms do not change that licence and do not restrict what it permits for the code.

The SDK is a client library. The services it calls run in PentAGI Cloud and are not part of the SDK. Access to them is a separate matter and is governed by this document.

## 2. Editions of PentAGI

PentAGI is distributed in two editions:

- the open-source edition, licensed under the MIT License;
- PentAGI Enterprise, which is proprietary software licensed only under the PentAGI Enterprise End User License Agreement (<https://pentagi.com/eula/>) or under a written agreement with VXControl.

Commercial use of PentAGI Enterprise is prohibited without a trial or paid licence. A company that wants to evaluate it requests a trial licence through the form at <https://console.pentagi.com>.

## 3. Access to PentAGI Cloud

Some PentAGI Cloud services, such as the update check, can be used without a licence key; the others require one, and what a licence key gives access to depends on its licence. For PentAGI Enterprise, the use of PentAGI Cloud is governed by the PentAGI Enterprise EULA or the written agreement with VXControl, not by this document. A licence key is personal to its holder and must not be shared with third parties.

A service may be changed, limited, suspended or withdrawn, and access may be refused or ended, in particular for a breach of these terms. Services are provided as they are, without a warranty of availability, accuracy or fitness for a purpose, to the extent the law of the United Arab Emirates permits.

## 4. Permitted use

The services and what they return may be used only for lawful security work on systems you own or are authorised in writing to test or protect: defensive security, authorised penetration testing, security research, incident response, education and compliance assessment.

You must not use the services or their results to:

- gain unauthorised access to a system, or to attack, disrupt or damage a system or a service;
- break the law, or the rights of a third party;
- circumvent technical or usage limits, or interfere with the operation of PentAGI Cloud;
- resell the services or access to them, or use the services or their results to build a competing service, without the written permission of VXControl.

Results, in particular those produced by AI models, can be wrong or incomplete and are to be checked before they are relied on.

## 5. Data

What reaches PentAGI Cloud depends on the feature of the server that a client calls and on how the client uses it. Each service receives the data the client sends to it for that feature, in the volume that feature needs. To provide a feature, PentAGI Cloud passes that data to the service providers it uses for that feature, in the minimum volume necessary. Every call also carries the installation identifier the client gives the SDK and, when the client gives one, its licence key, and PentAGI Cloud receives the network address of each request.

The SDK includes a client-side anonymizer (package `anonymizer`) that an integrating application may apply to data before it sends it. The SDK does not apply it on its own. The integrating application decides what to send and whether to anonymise it, and is responsible for having the right to send that data.

In PentAGI, the data of flows is stored locally, on the premises of the installation; a feature that runs in PentAGI Cloud receives the part of it that feature needs. The open-source edition sends an update check with a summary of the installation in figures: the server's, which `UPDATE_CHECK_INTERVAL=0` turns off, and the installer's, each time the installer runs. PentAGI Enterprise also sends, for licensing, numeric records of use together with the licence key and unique technical identifiers of the installation. These are part of the licensing mechanism and are not personal data.

Report a vulnerability in the SDK or in PentAGI Cloud to security@vxcontrol.com.

## 6. Liability

To the maximum extent permitted by law, VXControl is not liable for any loss or damage arising out of or related to the SDK or the services, whether direct or indirect, including loss of profit or data. You are responsible for your use of the SDK and the services, and for the systems you test with them.

## 7. Changes

VXControl may change these terms by publishing a new version in this repository. Continued use of the services after a change means acceptance of the new version.

## 8. Governing law and contact

These terms are governed by the laws of the United Arab Emirates. The competent courts of Dubai have exclusive jurisdiction over any dispute arising from them.

Legal questions: legal@vxcontrol.com. Licence keys and trial licences: <https://console.pentagi.com>.
