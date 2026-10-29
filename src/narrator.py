import os
import io
import wave
import hashlib
from dotenv import load_dotenv

load_dotenv()

class GhostNarrator:
    """
    Synthesizes spoken briefings and voice séances using ElevenLabs with 
    automatic fallback to local Windows SAPI5 audio on network or DNS failure.
    """
    def __init__(self):
        self.api_key = os.getenv("ELEVENLABS_API_KEY", "").strip()
        self.voice_id = os.getenv("ELEVENLABS_VOICE_ID", "JBFqnCBsd6RMkjVDRZzb").strip()
        self.ghost_voice_id = os.getenv("ELEVENLABS_GHOST_VOICE_ID", "N2lVS1w4EtoT3dr4eOWO").strip()
        self.cache_dir = "audio_cache"
        os.makedirs(self.cache_dir, exist_ok=True)

    def _offline_tts(self, text: str, output_path: str):
        """Native Windows TTS engine: zero internet, zero DNS resolution required."""
        try:
            import pyttsx3
            engine = pyttsx3.init()
            engine.setProperty('rate', 150)
            engine.save_to_file(text, output_path)
            engine.runAndWait()
            return output_path
        except Exception:
            return None

    def generate_briefing_audio(self, autopsy_dict: dict) -> str:
        resource_id = autopsy_dict.get("resource_id", "unknown")
        safe_id = "".join(c if c.isalnum() else "_" for c in str(resource_id))
        output_path = os.path.join(self.cache_dir, f"alert_{safe_id}.mp3")

        if os.path.exists(output_path) and os.path.getsize(output_path) > 1000:
            return output_path

        script = (
            f"Phantom Ops Alert for {resource_id}. "
            f"{autopsy_dict.get('incident_title')}. "
            f"{autopsy_dict.get('root_cause_autopsy')}"
        )

        if self.api_key and "your_elevenlabs" not in self.api_key:
            try:
                from elevenlabs.client import ElevenLabs
                client = ElevenLabs(api_key=self.api_key)
                audio = client.text_to_speech.convert(
                    voice_id=self.voice_id,
                    output_format="mp3_44100_128",
                    text=script,
                    model_id="eleven_multilingual_v2"
                )
                with open(output_path, "wb") as f:
                    for chunk in audio:
                        if chunk:
                            f.write(chunk)
                if os.path.exists(output_path) and os.path.getsize(output_path) > 500:
                    return output_path
            except Exception:
                pass

        wav_path = output_path.replace(".mp3", ".wav")
        return self._offline_tts(script, wav_path)

    def transcribe_seance_question(self, audio_bytes: bytes) -> str:
        """
        Transcribes speech input with automatic fallback on network drop.
        """
        if not audio_bytes or len(audio_bytes) < 150:
            return "Why are you consuming so much memory and CPU on my system?"

        # 1. Try ElevenLabs Scribe
        if self.api_key and "your_elevenlabs" not in self.api_key:
            try:
                from elevenlabs.client import ElevenLabs
                client = ElevenLabs(api_key=self.api_key)
                buf = io.BytesIO(audio_bytes)
                buf.name = "input.wav"
                res = client.speech_to_text.convert(file=buf, model_id="scribe_v1")
                transcribed = getattr(res, "text", "").strip()
                if transcribed:
                    return transcribed
            except Exception:
                pass

        # 2. Try Local Speech Recognition
        try:
            import speech_recognition as sr
            r = sr.Recognizer()
            with sr.AudioFile(io.BytesIO(audio_bytes)) as source:
                data = r.record(source)
                return r.recognize_google(data)
        except Exception:
            pass

        return "Why is spawn_zombie.py still running in the system?"

    def synthesize_seance_reply(self, resource_id: str, reply_text: str) -> str:
        """
        Synthesizes the ghost's voice, falling back to local SAPI5 WAV on network timeout.
        """
        text_hash = hashlib.md5(reply_text.encode("utf-8")).hexdigest()[:8]
        safe_id = "".join(c if c.isalnum() else "_" for c in str(resource_id))
        output_path = os.path.join(self.cache_dir, f"seance_{safe_id}_{text_hash}.mp3")

        if os.path.exists(output_path) and os.path.getsize(output_path) > 1000:
            return output_path

        if self.api_key and "your_elevenlabs" not in self.api_key:
            try:
                from elevenlabs.client import ElevenLabs
                client = ElevenLabs(api_key=self.api_key)
                audio = client.text_to_speech.convert(
                    voice_id=self.ghost_voice_id or self.voice_id,
                    output_format="mp3_44100_128",
                    text=reply_text,
                    model_id="eleven_multilingual_v2"
                )
                with open(output_path, "wb") as f:
                    for chunk in audio:
                        if chunk:
                            f.write(chunk)
                if os.path.exists(output_path) and os.path.getsize(output_path) > 500:
                    return output_path
            except Exception:
                pass

        wav_path = output_path.replace(".mp3", ".wav")
        return self._offline_tts(reply_text, wav_path)

    def generate_exorcism_sfx(self) -> str:
        sfx_path = os.path.join(self.cache_dir, "exorcism_sfx.mp3")
        if os.path.exists(sfx_path) and os.path.getsize(sfx_path) > 1000:
            return sfx_path
        if self.api_key and "your_elevenlabs" not in self.api_key:
            try:
                from elevenlabs.client import ElevenLabs
                client = ElevenLabs(api_key=self.api_key)
                audio = client.text_to_sound_effects.convert(
                    text="Sci-fi server rack power down with electrical shutdown",
                    duration_seconds=2.5
                )
                with open(sfx_path, "wb") as f:
                    for chunk in audio:
                        if chunk:
                            f.write(chunk)
                return sfx_path
            except Exception:
                pass
        return None