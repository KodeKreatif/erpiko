#define CATCH_CONFIG_MAIN
#include "catch.hpp"

#include "erpiko/time.h"

namespace Erpiko {

SCENARIO("Basic time test") {
  GIVEN("A new time") {
    Time *time = new Time("161012024321Z");
    REQUIRE(time->year() == 2016);
    REQUIRE(time->month() == 10);
    REQUIRE(time->day() == 12);
    REQUIRE(time->hours() == 2);
    REQUIRE(time->minutes() == 43);
    REQUIRE(time->seconds() == 21);
    delete(time);
    time = nullptr;
    REQUIRE(time == nullptr);
  }

  GIVEN("A new time on the heap") {
    Time t("161012024321Z");
    THEN("Time is parsed correctly") {
      REQUIRE(t.year() == 2016);
      REQUIRE(t.month() == 10);
      REQUIRE(t.day() == 12);
      REQUIRE(t.hours() == 2);
      REQUIRE(t.minutes() == 43);
      REQUIRE(t.seconds() == 21);
    }
  }
}

SCENARIO("UTC vs generalized time parsing") {
  GIVEN("A new time on the heap between 1950 and 2049, month is under 10") {
    Time t("800212345621Z");
    THEN("Time is parsed correctly") {
      REQUIRE(t.year() == 1980);
      REQUIRE(t.month() == 2);
      REQUIRE(t.day() == 12);
      REQUIRE(t.hours() == 34);
      REQUIRE(t.minutes() == 56);
      REQUIRE(t.seconds() == 21);
    }
  }

  GIVEN("A new time on the heap between 1950 and 2049, day is under 10") {
    Time t("801202345621Z");
    THEN("Time is parsed correctly") {
      REQUIRE(t.year() == 1980);
      REQUIRE(t.month() == 12);
      REQUIRE(t.day() == 2);
      REQUIRE(t.hours() == 34);
      REQUIRE(t.minutes() == 56);
      REQUIRE(t.seconds() == 21);
    }
  }

  GIVEN("A new time on the heap between 1950 and 2049, hours is under 10") {
    Time t("801202045621Z");
    THEN("Time is parsed correctly") {
      REQUIRE(t.year() == 1980);
      REQUIRE(t.month() == 12);
      REQUIRE(t.day() == 2);
      REQUIRE(t.hours() == 4);
      REQUIRE(t.minutes() == 56);
      REQUIRE(t.seconds() == 21);
    }
  }

  GIVEN("A new time on the heap between 1950 and 2049, minutes is under 10") {
    Time t("801202040621Z");
    THEN("Time is parsed correctly") {
      REQUIRE(t.year() == 1980);
      REQUIRE(t.month() == 12);
      REQUIRE(t.day() == 2);
      REQUIRE(t.hours() == 4);
      REQUIRE(t.minutes() == 6);
      REQUIRE(t.seconds() == 21);
    }
  }

  GIVEN("A new time on the heap between 1950 and 2049, seconds is under 10") {
    Time t("801202040601Z");
    THEN("Time is parsed correctly") {
      REQUIRE(t.year() == 1980);
      REQUIRE(t.month() == 12);
      REQUIRE(t.day() == 2);
      REQUIRE(t.hours() == 4);
      REQUIRE(t.minutes() == 6);
      REQUIRE(t.seconds() == 1);
    }
  }

  GIVEN("A new time on the heap before 1950") {
    Time t("19200212345621Z");
    THEN("Time is parsed correctly") {
      REQUIRE(t.year() == 1920);
      REQUIRE(t.month() == 2);
      REQUIRE(t.day() == 12);
      REQUIRE(t.hours() == 34);
      REQUIRE(t.minutes() == 56);
      REQUIRE(t.seconds() == 21);
    }
  }

  GIVEN("A new time on the heap after 2049") {
    Time t("20500212345621Z");
    THEN("Time is parsed correctly") {
      REQUIRE(t.year() == 2050);
      REQUIRE(t.month() == 2);
      REQUIRE(t.day() == 12);
      REQUIRE(t.hours() == 34);
      REQUIRE(t.minutes() == 56);
      REQUIRE(t.seconds() == 21);
    }
  }
}

SCENARIO("UTC vs generalized time construction") {
  GIVEN("A new time on the heap between 1950 and 2049, month is under 10") {
    std::string ref("800212345621Z");
    Time t;
    THEN("Time is constructed correctly") {
      t.year(1980);
      t.month(2);
      t.day(12);
      t.hours(34);
      t.minutes(56);
      t.seconds(21);
      REQUIRE(t.toString() == ref);
    }
  }

  GIVEN("A new time on the heap between 1950 and 2049, day is under 10") {
    std::string ref("801202345621Z");
    Time t;
    THEN("Time is constructed correctly") {
      t.year(1980);
      t.month(12);
      t.day(2);
      t.hours(34);
      t.minutes(56);
      t.seconds(21);
      REQUIRE(t.toString() == ref);
    }
  }

  GIVEN("A new time on the heap between 1950 and 2049, hours is under 10") {
    std::string ref("801202045621Z");
    Time t;
    THEN("Time is constructed correctly") {
      t.year(1980);
      t.month(12);
      t.day(2);
      t.hours(4);
      t.minutes(56);
      t.seconds(21);
      REQUIRE(t.toString() == ref);
    }
  }

  GIVEN("A new time on the heap between 1950 and 2049, minutes is under 10") {
    std::string ref("801202040621Z");
    Time t;
    THEN("Time is constructed correctly") {
      t.year(1980);
      t.month(12);
      t.day(2);
      t.hours(4);
      t.minutes(6);
      t.seconds(21);
      REQUIRE(t.toString() == ref);
    }
  }

  GIVEN("A new time on the heap between 1950 and 2049, seconds is under 10") {
    std::string ref("801202040601Z");
    Time t;
    THEN("Time is constructed correctly") {
      t.year(1980);
      t.month(12);
      t.day(2);
      t.hours(4);
      t.minutes(6);
      t.seconds(1);
      REQUIRE(t.toString() == ref);
    }
  }

  GIVEN("A new time on the heap before 1950") {
    std::string ref("19200212345621Z");
    Time t;
    THEN("Time is constructed correctly") {
      t.year(1920);
      t.month(2);
      t.day(12);
      t.hours(34);
      t.minutes(56);
      t.seconds(21);
      REQUIRE(t.toString() == ref);
    }
  }

  GIVEN("A new time on the heap after 2049") {
    std::string ref("20500212345621Z");
    Time t;
    THEN("Time is constructed correctly") {
      t.year(2050);
      t.month(2);
      t.day(12);
      t.hours(34);
      t.minutes(56);
      t.seconds(21);
      REQUIRE(t.toString() == ref);
    }
  }
}

SCENARIO("In range") {
  GIVEN("Three Times, now being same with before, one sec before after") {
    Time tBefore("800212345621Z");
    Time tNow("800212345621Z");
    Time tAfter("800212345622Z");
    THEN("in range is correctly computed") {
      REQUIRE(tNow.inRange(tBefore, tAfter));
    }
  }

  GIVEN("Three Times, now being one sec after before") {
    Time tBefore("800212345620Z");
    Time tNow("800212345621Z");
    Time tAfter("800212345622Z");
    THEN("in range is correctly computed") {
      REQUIRE(tNow.inRange(tBefore, tAfter));
    }
  }

  GIVEN("Three Times, after being same with now") {
    Time tBefore("800212345621Z");
    Time tNow("800212345621Z");
    Time tAfter("800212345621Z");
    THEN("in range is correctly computed") {
      REQUIRE_FALSE(tNow.inRange(tBefore, tAfter));
    }
  }

}

SCENARIO("Assignment") {
  GIVEN("Two different Times") {
    Time t1("800212345621Z");
    Time t2("800212345620Z");
    THEN("They are different") {
      REQUIRE_FALSE(t1 == t2);
      GIVEN("One is assigned to another") {
        t1 = t2;
        THEN("They are now the same") {
          REQUIRE(t1 == t2);
        }
      }
    }
  }
}


} //namespace Erpiko
