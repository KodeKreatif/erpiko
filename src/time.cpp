#include "erpiko/time.h"
#include <ctime>

namespace Erpiko {

class Time::Impl {
  public:
    struct tm timeData;

    Impl(const std::string asn1 = "") : timeData(fromString(asn1)) {
    }

    virtual ~Impl() = default;

    struct tm fromString(const std::string &str)
    {
      struct tm t;
      if (str == "") {
        time_t now;
        struct tm * timeinfo;

        now = time(NULL);
        timeinfo = localtime(&now);
        t.tm_year = timeinfo->tm_year;
        t.tm_mon = timeinfo->tm_mon;
        t.tm_mday = timeinfo->tm_mday;
        t.tm_hour = timeinfo->tm_hour;
        t.tm_min = timeinfo->tm_min;
        t.tm_sec = timeinfo->tm_sec;
        return t;
      };

      unsigned short length = 4; // GeneralizedTime
      unsigned short pos = 0;

      if (str.size() == 13) {
        // UTC Time
        length = 2;
      }

      std::string tmp;
      tmp = str.substr(0, length);
      t.tm_year = atoi(tmp.c_str());
      if (length == 2) {
        // two digits year version
        if (t.tm_year >= 50) {
          t.tm_year = 1900 + t.tm_year;
        } else {
          t.tm_year = 2000 + t.tm_year;
        }
      }

      pos += length;

      tmp = str.substr(pos, 2);
      t.tm_mon = atoi(tmp.c_str());
      pos += 2;

      tmp = str.substr(pos, 2);
      t.tm_mday = atoi(tmp.c_str());
      pos += 2;

      tmp = str.substr(pos, 2);
      t.tm_hour = atoi(tmp.c_str());
      pos += 2;

      tmp = str.substr(pos, 2);
      t.tm_min = atoi(tmp.c_str());
      pos += 2;

      tmp = str.substr(pos, 2);
      t.tm_sec = atoi(tmp.c_str());
      pos += 2;
      return t;
    }

    std::string toString(const struct tm time)
    {
      std::string value;

      if (time.tm_year >= 1950 && time.tm_year <= 2049) {
        // This is UTC. It reserves only 2 digits for the year
        unsigned int year;
        if (time.tm_year >= 2000) {
          year = time.tm_year - 2000;
        } else {
          year = time.tm_year - 1900;
        }

        if (year < 10) {
          value += "0";
        }

        value += std::to_string(year);
      } else {
        // This is generalized time, we have full 4 digits
        value += std::to_string(time.tm_year);
      }

      if (time.tm_mon < 10) {
        // prepend month lower than 10 so it will occupy 2 digits
        value += "0";
      }
      value += std::to_string(time.tm_mon);

      if (time.tm_mday < 10) {
        // same thing happens with the day
        value += "0";
      }
      value += std::to_string(time.tm_mday);

      if (time.tm_hour < 10) {
        // and the hour
        value += "0";
      }
      value += std::to_string(time.tm_hour);

      if (time.tm_min < 10) {
        // and the minutes
        value += "0";
      }
      value += std::to_string(time.tm_min);

      if (time.tm_sec < 10) {
        // as well ass the seconds
        value += "0";
      }
      value += std::to_string(time.tm_sec);

      value += "Z";
      return value;
    }
};

Time::Time(const std::string asn1) : impl{std::make_unique<Impl>(asn1)} {
}

Time::~Time() = default;

const std::string Time::toString() const {
  return impl->toString(impl->timeData);
}

int Time::year() const {
  return impl->timeData.tm_year;
}

void Time::year(const int value) {
  impl->timeData.tm_year = value;
}

int Time::month() const {
  return impl->timeData.tm_mon;
}

void Time::month(const int value) {
  impl->timeData.tm_mon = value;
}

int Time::day() const {
  return impl->timeData.tm_mday;
}

void Time::day(const int value) {
  impl->timeData.tm_mday = value;
}

int Time::hours() const {
  return impl->timeData.tm_hour;
}

void Time::hours(const int value) {
  impl->timeData.tm_hour = value;
}

int Time::minutes() const {
  return impl->timeData.tm_min;
}

void Time::minutes(const int value) {
  impl->timeData.tm_min = value;
}

int Time::seconds() const {
  return impl->timeData.tm_sec;
}

void Time::seconds(const int value) {
  impl->timeData.tm_sec = value;
}

bool Time::inRange(const Time& notBefore, const Time& notAfter) const {
  auto eBefore = mktime(&notBefore.impl->timeData);
  auto eAfter = mktime(&notAfter.impl->timeData);
  auto now = mktime(&impl->timeData);

  return (now >= eBefore && now < eAfter);
}

} // namespace Erpiko
