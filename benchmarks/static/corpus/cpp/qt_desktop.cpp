// SPDX-License-Identifier: Apache-2.0
// Qt desktop SAST guards: QProcess single-string/native-argument command launch
// and QSqlQuery concatenated SQL are unsafe; list-form process arguments and
// prepared/bound SQL stay clean.

#include <QProcess>
#include <QLocale>
#include <QSqlQuery>

void unsafe_qt_process(QProcess *process, const QString &userCommand, const QString &userProgram) {
    process->startCommand(userCommand);                         // EXPECT GF-304
    process->start("sh", QStringList() << "-c" << userCommand); // EXPECT GF-404
    QProcess::startDetached(userProgram, QStringList());        // EXPECT GF-304
}

void safe_qt_process(QProcess *process) {
    process->startCommand("git status");
    process->start("/usr/bin/git", QStringList() << "status");
    process->setProgram("/usr/bin/git");
    process->setArguments(QStringList() << "status");
    process->start();
    QProcess::startDetached("/usr/bin/git", QStringList() << "status");
    auto text = "process->startCommand(userCommand)";
}

QString safe_qt_locale_format(double value) {
    return QLocale::system().toString(value, 'f', 2);
}

void unsafe_qt_sql(QSqlDatabase db, const QString &userName) {
    QSqlQuery query(db);
    query.exec("SELECT * FROM users WHERE name='" + userName + "'"); // EXPECT GF-419
    QSqlQuery inlineQuery("DELETE FROM audit WHERE actor='" + userName + "'", db); // EXPECT GF-419
}

void unsafe_cpp_log(const QString &userInput) {
    spdlog::warn("{}", userInput); // EXPECT GF-544
}

void safe_qt_sql(QSqlDatabase db, const QString &userName) {
    QSqlQuery query(db);
    query.prepare("SELECT * FROM users WHERE name=?");
    query.bindValue(0, userName);
    query.exec();
    QSqlQuery inlineQuery("SELECT * FROM users WHERE name=?", db);
    auto text = "query.exec(\"SELECT \" + userName)";
}

void safe_cpp_log() {
    spdlog::info("fixed");
}
