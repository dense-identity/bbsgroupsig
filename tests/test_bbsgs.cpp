#include <chrono>
#include <catch2/catch_test_macros.hpp>

SCENARIO("Sample Scenario", "[example]") {
    GIVEN("a sample information") {
        WHEN("1 equals 1") {
            REQUIRE(1 == 1);
            THEN("it can never be 2") {
                REQUIRE(1 != 2);
            }
        }
    }
}