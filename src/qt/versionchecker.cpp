#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include <qt/versionchecker.h>
#include <clientversion.h>
#include "tinyformat.h"
#include "util.h"

#include <set>
//#include <iostream>

// #include <QNetworkAccessManager>
// #include <QNetworkRequest>
// #include <QNetworkReply>
// #include <QEventLoop>

// Qt features: -no-feature-regularexpression
// #include <QRegularExpression>
// #include <QRegularExpressionMatchIterator>

#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QJsonValue>

#include <curl/curl.h>
#include <curl/easy.h>

#define patternVersion "v([0-9]+\\.)?([0-9]+\\.)?([0-9]+)-"

KomodoVersionChecker::KomodoVersionChecker(QObject *parent) : QObject(parent)
{
    currentVersion = Version(CLIENT_VERSION_MAJOR, CLIENT_VERSION_MINOR, CLIENT_VERSION_REVISION);
}

KomodoVersionChecker::~KomodoVersionChecker()
{

}

bool KomodoVersionChecker::newVersionAvailable()
{
    Version maxReleaseVersion = getMaxReleaseVersion();
    bool fUpdateNeeded = maxReleaseVersion > currentVersion;
    if (fUpdateNeeded)
        LogPrintf("%s: maxReleaseVersion = %s, currentVersion = %s\n", __func__, maxReleaseVersion.ToString(), currentVersion.ToString());
    return fUpdateNeeded;
}

static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

static const std::set<std::string> tags_to_ignore = {
    "v3.0.1-beta5",
    "v3.0.1-beta4",
    "v3.0.1-beta3-b8d315b",
    "v3.0.1-beta3-b6f33fa",
    "v3.0.1-beta2-27f2631",
    "v3.0.1-beta2-2d7fe5c",
    "v3.0.0-beta1-9979ca2",
    "v2.0.15-rc2-g28",
    "v2.0.15-rc2-g28-7",
    "v2.0.15-rc2-g28-6",
    "v2.0.15-rc2-g28-5",
    "v2.0.15-rc2-g28-4",
    "v2.0.15-rc2-g28-3",
    "v2.0.15-rc2-g28-2",
    "v2.0.15-rc2-g28-1",
    "v2.0.15-rc2-g27",
    "v2.0.15-rc2-g27-3",
    "v2.0.15-rc2-g27-2",
    "v2.0.15-rc2-g27-1",
    "v1.1.4qt",
    "komodoqt_win64_build26_26042018",
    "komodoqt_win64_build26_24042018",
    "komodoqt_win64_build26_16072018",
    "komodoqt_win64_build26_03102018",
    "komodoqt_win64_build26_03072018",
    "komodoqt_win64_build26_03052018"
};

// #pragma GCC push_options
// #pragma GCC optimize ("O0")
QList<Version> KomodoVersionChecker::getVersions()
{
    QList<Version> versions;

    /* QNetworkAccessManager manager;
    QNetworkReply *response = manager.get(QNetworkRequest(QUrl(KOMODO_RELEASES)));
    QEventLoop event;
    connect(response, &QNetworkReply::finished, &event, &QEventLoop::quit);
    event.exec();

    if( response->error() == QNetworkReply::NoError ) {

        QString html = response->readAll();

        QRegularExpression regEx(patternVersion);
        QRegularExpressionMatchIterator regExIt = regEx.globalMatch(html);

        while (regExIt.hasNext()) {
            QRegularExpressionMatch match = regExIt.next();
            QString versionString = match.captured().mid(5, match.captured().length() - 6); // get version string in format XX.XX.XX
            Version version(versionString);
            if(!versions.contains(version))
            {
                versions.append(version);
            }
        }
    }
    else
    {
        // Protocol "https" is unknown
        std::cerr << response->errorString().toStdString() << std::endl;
    }
    response->deleteLater(); */

    CURL *curl_handle = curl_easy_init();
    if (curl_handle)
    {
        std::string readBuffer;

        CURLcode res;
        curl_easy_setopt(curl_handle, CURLOPT_URL, KOMODO_RELEASES);
        curl_easy_setopt(curl_handle,CURLOPT_USERAGENT,"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.71 Safari/537.36");

        curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, 0L);
        // curl_easy_setopt(curl_handle, CURLOPT_VERBOSE, 1L);

        curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, &readBuffer);

        res = curl_easy_perform(curl_handle);
        if ( res == CURLE_OK ) {

            // https://stackoverflow.com/questions/19822211/qt-parsing-json-using-qjsondocument-qjsonobject-qjsonarray
            // https://stackoverflow.com/questions/49641219/parse-unnamed-json-array-from-a-web-service-in-qt

            QString val = QString::fromStdString(readBuffer);
            QJsonParseError parseError;
            QJsonDocument doc = QJsonDocument::fromJson(val.toUtf8(), &parseError);
            if (parseError.error == QJsonParseError::NoError)
            {
                if (doc.isArray())
                {
                    // QJsonObject jsonObject = doc.object();
                    QJsonArray jsonArray = doc.array();
                    for (const QJsonValue & value : jsonArray) {
                        QJsonObject obj = value.toObject();
                        QString versionString = obj["name"].toString();
                        if (!tags_to_ignore.count(versionString.toStdString())) {
                            Version version(versionString);
                            // std::cerr << versionString.toStdString() << " - " << version.ToString() << std::endl;
                            if(!versions.contains(version))
                            {
                                versions.append(version);
                            }
                        }
                    }
                }
            }
        }

        curl_easy_cleanup(curl_handle);
    }

    return versions;
}
//#pragma GCC pop_options

Version KomodoVersionChecker::getMaxReleaseVersion()
{
    QList<Version> versions = getVersions();
    Version maxVersion;

    if(!versions.isEmpty())
    {
        maxVersion = *std::max_element(versions.begin(), versions.end());
    }
    return maxVersion;
}

std::string Version::ToString() const {
    return strprintf("%d.%d.%d", _major, _minor, _revision);
}
