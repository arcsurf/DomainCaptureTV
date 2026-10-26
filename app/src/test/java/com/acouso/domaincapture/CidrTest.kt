package com.acouso.domaincapture

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class CidrTest {

    private fun c(s: String) = Cidr.parse(s)!!
    private fun agg(vararg s: String) = Cidr.aggregate(s.map(::c)).map { it.toString() }

    @Test fun parsesAndAlignsToMask() {
        assertEquals("45.57.40.0/24", c("45.57.40.77/24").toString())
        assertEquals("1.2.3.4/32", c("1.2.3.4").toString())
        assertEquals("2a00:86c0::/32", c("2a00:86c0:1234::1/32").toString())
        assertEquals("2a00:86c0:0:1::/64", c("2a00:86c0:0:1:5::/64").toString())
        assertEquals("::/0", c("::/0").toString())
        assertNull(Cidr.parse("netflix.com"))
        assertNull(Cidr.parse("1.2.3.4/33"))
    }

    @Test fun mergesContiguousHalvesRecursively() {
        assertEquals(listOf("10.0.0.0/22"), agg("10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"))
        assertEquals(listOf("10.0.1.0/24", "10.0.2.0/24"), agg("10.0.1.0/24", "10.0.2.0/24"))
        assertEquals(listOf("2a00:86c0::/31"), agg("2a00:86c0::/32", "2a00:86c1::/32"))
    }

    @Test fun removesCoveredBlocksAndSortsV4First() {
        assertEquals(
            listOf("45.57.0.0/17", "2a00:86c0::/32"),
            agg("2a00:86c0:5::/48", "45.57.40.0/24", "2a00:86c0::/32", "45.57.0.0/17", "45.57.40.9"),
        )
        // un hueco impide la unión
        assertEquals(listOf("1.0.0.0/24", "1.0.2.0/23"), agg("1.0.0.0/24", "1.0.2.0/24", "1.0.3.0/24"))
    }

    @Test fun reservedAddressesAreNotPublic() {
        assertFalse(Cidr.isPublic(c("192.168.1.10")))
        assertFalse(Cidr.isPublic(c("0.0.0.0")))
        assertFalse(Cidr.isPublic(c("fd00::1")))
        assertTrue(Cidr.isPublic(c("45.57.40.1")))
        assertTrue(Cidr.isPublic(c("2a00:86c0::1")))
    }
}
