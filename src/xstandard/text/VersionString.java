package xstandard.text;

/**
 * Utility class for comparing semantic version strings (e.g. "1.2.3").
 */
public class VersionString implements Comparable<VersionString> {

	private final String versionStr;
	private final int[] segments;

	public VersionString(String version) {
		this.versionStr = version != null ? version : "0";
		String[] parts = this.versionStr.split("\\.");
		segments = new int[parts.length];
		for (int i = 0; i < parts.length; i++) {
			try {
				segments[i] = Integer.parseInt(parts[i]);
			} catch (NumberFormatException e) {
				segments[i] = 0;
			}
		}
	}

	@Override
	public int compareTo(VersionString other) {
		int len = Math.max(segments.length, other.segments.length);
		for (int i = 0; i < len; i++) {
			int a = i < segments.length ? segments[i] : 0;
			int b = i < other.segments.length ? other.segments[i] : 0;
			if (a != b) {
				return Integer.compare(a, b);
			}
		}
		return 0;
	}

	public boolean isNewerThan(VersionString other) {
		return compareTo(other) > 0;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj instanceof VersionString) {
			return compareTo((VersionString) obj) == 0;
		}
		return false;
	}

	@Override
	public int hashCode() {
		int hash = 0;
		for (int seg : segments) {
			hash = hash * 31 + seg;
		}
		return hash;
	}

	@Override
	public String toString() {
		return versionStr;
	}
}
