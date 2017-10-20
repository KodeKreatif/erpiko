#ifndef _ETIME_H_
#define _ETIME_H_

#include <string>
#include <memory>

namespace Erpiko {

class Time {
  public:
    /**
     * Constructs new time from ASN1 string
     * @param asn1 the ASN1 string, if empty it will generate local time
     */
    Time(const std::string asn1 = "");
    virtual ~Time();

    /**
     * Return ASN1 string representation of the time
     * @return ASN1 string
     */
    const std::string toString() const;

    /**
     * Returns year
     * @return year
     */
    int year() const;

    /**
     * Sets the year
     * @param year the new year
     */
    void year(const int value);

    /**
     * Returns month
     * @return month
     */
    int month() const;

    /**
     * Sets the month
     * @param month the new month
     */
    void month(const int value);

    /**
     * Returns day
     * @return day
     */
    int day() const;

    /**
     * Sets the day
     * @param day the new day
     */
    void day(const int value);

    /**
     * Returns hours
     * @return hours
     */
    int hours() const;

    /**
     * Sets the hours
     * @param hours the new hours
     */
    void hours(const int value);

    /**
     * Returns minutes
     * @return minutes
     */
    int minutes() const;

    /**
     * Sets the minutes
     * @param minutes the new minutes
     */
    void minutes(const int value);

    /**
     * Returns seconds
     * @return seconds
     */
    int seconds() const;

    /**
     * Sets the seconds
     * @param seconds the new seconds
     */
    void seconds(const int value);

    /**
     * Checks whether the time is in specified range
     */
    bool inRange(const Time& notBefore, const Time& notAfter) const;

    /**
     * Operator =
     */
    void operator=(const Time &other);

    /**
     * Operator ==
     */
    bool operator==(const Time &other) const;

    /**
     * Operator <
     */
    bool operator<(const Time &other) const;

    /**
     * Operator >
     */
    bool operator>(const Time &other) const;



  private:
    class Impl;
    std::unique_ptr<Impl> impl;
};

} // namespace Erpiko
#endif // _ETIME_H_
