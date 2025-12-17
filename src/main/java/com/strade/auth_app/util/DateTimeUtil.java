package com.strade.auth_app.util;

import java.time.*;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;

/**
 * Utility class for date/time operations.
 * In this project, LocalDateTime is treated as Asia/Jakarta local time.
 */
public final class DateTimeUtil {

    private static final ZoneId ZONE_JAKARTA = ZoneId.of("Asia/Jakarta");

    private static final DateTimeFormatter ISO_FORMATTER = DateTimeFormatter.ISO_LOCAL_DATE_TIME;
    private static final DateTimeFormatter DISPLAY_FORMATTER =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private DateTimeUtil() {
        throw new IllegalStateException("Utility class");
    }

    /**
     * Get current LocalDateTime in Asia/Jakarta
     */
    public static LocalDateTime now() {
        return LocalDateTime.now(ZONE_JAKARTA);
    }

    /* ===================== ADD / MINUS OPS ===================== */

    public static LocalDateTime plusSeconds(LocalDateTime dateTime, long seconds) {
        return dateTime.plusSeconds(seconds);
    }

    public static LocalDateTime plusMinutes(LocalDateTime dateTime, long minutes) {
        return dateTime.plusMinutes(minutes);
    }

    public static LocalDateTime plusHours(LocalDateTime dateTime, long hours) {
        return dateTime.plusHours(hours);
    }

    public static LocalDateTime plusDays(LocalDateTime dateTime, long days) {
        return dateTime.plusDays(days);
    }

    public static LocalDateTime minusMinutes(LocalDateTime dateTime, long minutes) {
        return dateTime.minusMinutes(minutes);
    }

    public static LocalDateTime minusDays(LocalDateTime dateTime, long days) {
        return dateTime.minusDays(days);
    }

    /* ===================== COMPARISON ===================== */

    public static boolean isPast(LocalDateTime dateTime) {
        return dateTime.isBefore(now());
    }

    public static boolean isFuture(LocalDateTime dateTime) {
        return dateTime.isAfter(now());
    }

    /* ===================== FORMAT ===================== */

    public static String formatIso(LocalDateTime dateTime) {
        return ISO_FORMATTER.format(dateTime);
    }

    public static String formatDisplay(LocalDateTime dateTime) {
        return DISPLAY_FORMATTER.format(dateTime);
    }

    public static LocalDateTime parseIso(String isoString) {
        return LocalDateTime.parse(isoString, ISO_FORMATTER);
    }

    public static LocalDateTime parseDisplay(String displayString) {
        return LocalDateTime.parse(displayString, DISPLAY_FORMATTER);
    }

    /* ===================== DURATION ===================== */

    public static long secondsUntil(LocalDateTime targetDateTime) {
        return ChronoUnit.SECONDS.between(now(), targetDateTime);
    }

    public static long minutesUntil(LocalDateTime targetDateTime) {
        return ChronoUnit.MINUTES.between(now(), targetDateTime);
    }

    public static long secondsBetween(LocalDateTime start, LocalDateTime end) {
        return ChronoUnit.SECONDS.between(start, end);
    }

    /* ===================== TOTP SUPPORT ===================== */

    public static long getTotpTimeStep(int periodSeconds) {
        // TOTP hitungannya selalu UTC → langsung pakai Instant.now()
        long epochSeconds = Instant.now().getEpochSecond();
        return epochSeconds / periodSeconds;
    }

    /* ===================== SQL + INSTANT CONVERSION ===================== */

    public static java.sql.Timestamp toSqlTimestamp(LocalDateTime dateTime) {
        return java.sql.Timestamp.valueOf(dateTime);
    }

    public static LocalDateTime fromSqlTimestamp(java.sql.Timestamp timestamp) {
        return timestamp.toLocalDateTime();
    }

    /**
     * Convert LocalDateTime (Jakarta) → Instant (UTC)
     */
    public static Instant toInstant(LocalDateTime dateTime) {
        return dateTime.atZone(ZONE_JAKARTA).toInstant();
    }

    /**
     * Convert Instant (UTC) → LocalDateTime (Jakarta)
     */
    public static LocalDateTime fromInstant(Instant instant) {
        return LocalDateTime.ofInstant(instant, ZONE_JAKARTA);
    }

    /* ===================== DATE CONVERSION ===================== */

    public static java.util.Date toDate(LocalDateTime dateTime) {
        return java.util.Date.from(toInstant(dateTime));
    }

    public static LocalDateTime fromDate(java.util.Date date) {
        return LocalDateTime.ofInstant(date.toInstant(), ZONE_JAKARTA);
    }

    /* ===================== DAY START/END ===================== */

    public static LocalDateTime startOfToday() {
        return now().toLocalDate().atStartOfDay();
    }

    public static LocalDateTime endOfToday() {
        return now().toLocalDate().atTime(23, 59, 59);
    }

    /* ===================== TRUNCATION ===================== */

    public static LocalDateTime truncateToSeconds(LocalDateTime dateTime) {
        return dateTime.truncatedTo(ChronoUnit.SECONDS);
    }

    public static LocalDateTime truncateToMinutes(LocalDateTime dateTime) {
        return dateTime.truncatedTo(ChronoUnit.MINUTES);
    }

    /* ===================== RANGE ===================== */

    public static boolean isBetween(LocalDateTime dateTime, LocalDateTime start, LocalDateTime end) {
        return !dateTime.isBefore(start) && !dateTime.isAfter(end);
    }
}
